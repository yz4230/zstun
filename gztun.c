#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>
#include <linux/zstd.h>
#include <net/ip.h>
#include <net/rtnetlink.h>

#define DRV_NAME "gztun"
#define ZSTD_COMPRESSION_LEVEL 1
#define TUN_PORT 9999

struct percpu_ctx {
  void *zstd_wksp;
  size_t zstd_wksp_size;
  void *dst_buf;
  size_t dst_buf_size;
};

static struct percpu_ctx __percpu *percpu_ctxs;

struct gztun_struct {
  struct net_device *redirect_dev;
  netdevice_tracker tracker;
  zstd_parameters params;
};

static size_t zstd_max_input(size_t limit) {
  size_t low = 0, high = limit, mid;

  while (low < high) {
    mid = low + (high - low + 1) / 2;
    if (zstd_compress_bound(mid) <= limit)
      low = mid;
    else
      high = mid - 1;
  }

  return low;
}

static void free_gztun_struct(struct gztun_struct *gztun) {
  if (gztun->redirect_dev) {
    netdev_put(gztun->redirect_dev, &gztun->tracker);
    gztun->redirect_dev = NULL;
  }
}

static int check_proto(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;

  iph = ip_hdr(skb);
  if (iph->protocol != IPPROTO_UDP) {
    return -1;
  }
  udph = udp_hdr(skb);
  if (udph->dest != htons(TUN_PORT)) {
    return -1;
  }

  return 0;
}

static int make_skb_safe(struct sk_buff **pskb) {
  struct sk_buff *skb = *pskb;
  int ret;

  if (skb_shared(skb) || skb_cloned(skb)) {
    struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
    if (!nskb) {
      pr_err("gztun: failed to copy skb\n");
      return -ENOMEM;
    }
    dev_kfree_skb(skb);
    skb = nskb;
    *pskb = skb;
  }

  ret = skb_linearize(skb);
  if (ret != 0) {
    pr_err("gztun: skb_linearize failed: %d\n", ret);
    return ret;
  }

  return 0;
}

static int stretch_skb_size(struct sk_buff *skb, int size_diff) {
  int ret;
  if (size_diff > 0) {
    if (skb_tailroom(skb) < size_diff) {
      ret = pskb_expand_head(skb, 0, size_diff - skb_tailroom(skb), GFP_ATOMIC);
      if (ret != 0) {
        pr_err("gztun: failed to expand skb head\n");
        return ret;
      }
    }
  } else if (size_diff < 0) {
    skb_trim(skb, skb->len + size_diff);
  }
  return 0;
}

static netdev_tx_t gztun_start_xmit(struct sk_buff *skb, struct net_device *dev) {
  struct gztun_struct *gztun;
  struct percpu_ctx *ctx;
  zstd_cctx *cctx;
  int ret;

  int len_diff, udph_off, payload_off;
  size_t old_size, new_size;

  pr_info("gztun: start_xmit called, len=%u\n", skb->len);
  gztun = netdev_priv(dev);

  if (check_proto(skb) != 0) {
    pr_err("gztun: packet is not UDP to port %d, dropping\n", TUN_PORT);
    goto drop;
  }

  udph_off = skb_transport_offset(skb);
  payload_off = udph_off + sizeof(struct udphdr);
  old_size = skb->len - payload_off;

  if ((ret = make_skb_safe(&skb)) != 0) {
    pr_err("gztun: make_skb_safe failed: %d\n", ret);
    goto drop;
  }

  ctx = get_cpu_ptr(percpu_ctxs);
  cctx = zstd_init_cctx(ctx->zstd_wksp, ctx->zstd_wksp_size);
  if (!cctx) {
    pr_err("gztun: failed to initialize zstd cctx\n");
    put_cpu_ptr(percpu_ctxs);
    goto drop;
  }

  new_size = zstd_compress_cctx(cctx, ctx->dst_buf, ctx->dst_buf_size,
                                skb->data + payload_off, old_size, &gztun->params);
  if (zstd_is_error(new_size)) {
    pr_err("gztun: zstd compression failed: %s\n", zstd_get_error_name(new_size));
    zstd_free_cctx(cctx);
    put_cpu_ptr(percpu_ctxs);
    goto drop;
  }

  zstd_free_cctx(cctx);
  put_cpu_ptr(percpu_ctxs);

  len_diff = new_size - old_size;
  ret = stretch_skb_size(skb, len_diff);
  if (ret != 0) {
    pr_err("gztun: stretch_skb_size failed: %d\n", ret);
    goto drop;
  }

  memcpy(skb->data + payload_off, ctx->dst_buf, new_size);
  struct iphdr *iph = (struct iphdr *)skb->data;
  struct udphdr *udph = (struct udphdr *)(skb->data + udph_off);
  udph->len = htons(sizeof(struct udphdr) + new_size);
  iph->tot_len = htons(skb->len);
  udph->check = 0;
  udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, ntohs(udph->len), IPPROTO_UDP,
                                  csum_partial((char *)udph, ntohs(udph->len), 0));
  iph->check = 0;
  ip_send_check(iph);

  skb->dev = gztun->redirect_dev;
  dev_queue_xmit(skb);

  pr_info("gztun: packet compressed from %zu to %zu bytes and forwarded to %s\n",
          old_size, new_size, gztun->redirect_dev->name);
  return NETDEV_TX_OK;

drop:
  dev_kfree_skb(skb);
  return NETDEV_TX_OK;
}

static const struct net_device_ops gztun_netdev_ops = {
    .ndo_start_xmit = gztun_start_xmit,
    .ndo_set_mac_address = eth_mac_addr,
};

static void gztun_setup(struct net_device *dev) {
  ether_setup(dev);

  dev->netdev_ops = &gztun_netdev_ops;

  dev->needs_free_netdev = true;
  dev->flags |= IFF_NOARP;
  eth_hw_addr_random(dev);
}

static int gztun_validate(struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack) {
  if (!tb[IFLA_LINK]) {
    NL_SET_ERR_MSG(extack, "gztun: redirect device (IFLA_LINK) is required");
    return -EINVAL;
  }

  return 0;
}

static int alloc_percpu_ctxs(zstd_parameters *params, int parent_mtu) {
  int cpu;
  size_t zstd_wksp_size;
  size_t dst_buf_size;
  struct percpu_ctx *ctx;

  zstd_wksp_size = zstd_cctx_workspace_bound(&params->cParams);
  dst_buf_size = parent_mtu;

  for_each_possible_cpu(cpu) {
    ctx = per_cpu_ptr(percpu_ctxs, cpu);
    if (ctx->zstd_wksp_size < zstd_wksp_size) {
      kvfree(ctx->zstd_wksp);
      ctx->zstd_wksp = kvmalloc(zstd_wksp_size, GFP_KERNEL);
      if (!ctx->zstd_wksp) {
        pr_err("gztun: failed to allocate zstd workspace for CPU %d\n", cpu);
        return -ENOMEM;
      }
      ctx->zstd_wksp_size = zstd_wksp_size;
    }
    if (ctx->dst_buf_size < dst_buf_size) {
      kvfree(ctx->dst_buf);
      ctx->dst_buf = kvmalloc(dst_buf_size, GFP_KERNEL);
      if (!ctx->dst_buf) {
        pr_err("gztun: failed to allocate dst buffer for CPU %d\n", cpu);
        return -ENOMEM;
      }
      ctx->dst_buf_size = dst_buf_size;
    }
  }

  return 0;
}

static int gztun_newlink(struct net_device *dev, struct rtnl_newlink_params *params, struct netlink_ext_ack *extack) {
  pr_info("gztun: newlink called for device %s\n", dev->name);

  struct gztun_struct *gztun;
  struct nlattr **tb;
  struct net_device *link_dev;
  u32 ifindex;
  int err;

  gztun = netdev_priv(dev);
  gztun->redirect_dev = NULL;
  gztun->params = zstd_get_params(ZSTD_COMPRESSION_LEVEL, 0);
  tb = params->tb;

  if (tb[IFLA_LINK]) {
    ifindex = nla_get_u32(tb[IFLA_LINK]);
    link_dev = netdev_get_by_index(params->src_net, ifindex, &gztun->tracker, GFP_KERNEL);
    if (link_dev) {
      gztun->redirect_dev = link_dev;
      pr_info("gztun: linked to device %s\n", link_dev->name);
    } else {
      pr_err("gztun: failed to get device by index %u\n", ifindex);
      return -ENODEV;
    }
  } else {
    pr_err("gztun: no IFLA_LINK attribute provided\n");
    return -EINVAL;
  }

  int parent_mtu = READ_ONCE(gztun->redirect_dev->mtu);
  int mtu = zstd_max_input(parent_mtu);
  WRITE_ONCE(dev->mtu, mtu);
  pr_info("gztun: set MTU to %d (parent MTU %d)\n", mtu, parent_mtu);
  err = alloc_percpu_ctxs(&gztun->params, parent_mtu);
  if (err != 0) {
    free_gztun_struct(gztun);
    return err;
  }

  err = register_netdevice(dev);
  if (err) {
    pr_err("gztun: register_netdev failed: %d\n", err);
    free_gztun_struct(gztun);
    return err;
  }

  return 0;
}

static void gztun_dellink(struct net_device *dev, struct list_head *head) {
  struct gztun_struct *gztun = netdev_priv(dev);
  free_gztun_struct(gztun);
  unregister_netdevice_queue(dev, head);
}

static struct rtnl_link_ops gztun_link_ops = {
    .kind = DRV_NAME,
    .setup = gztun_setup,
    .validate = gztun_validate,
    .newlink = gztun_newlink,
    .dellink = gztun_dellink,
    .priv_size = sizeof(struct gztun_struct),
};

static void free_percpu_ctxs(void) {
  int cpu;

  if (!percpu_ctxs)
    return;

  for_each_possible_cpu(cpu) {
    struct percpu_ctx *ctx = per_cpu_ptr(percpu_ctxs, cpu);
    if (ctx->zstd_wksp)
      kvfree(ctx->zstd_wksp);
    if (ctx->dst_buf)
      kvfree(ctx->dst_buf);
  }
  free_percpu(percpu_ctxs);
  percpu_ctxs = NULL;
}

static int __init gztun_netdev_init(void) {
  int err;
  pr_info("gztun: initializing\n");

  percpu_ctxs = alloc_percpu(struct percpu_ctx);
  if (!percpu_ctxs)
    return -ENOMEM;

  err = rtnl_link_register(&gztun_link_ops);
  if (err < 0) {
    pr_err("gztun: failed to register rtnl link ops\n");
    free_percpu_ctxs();
    return err;
  }

  return 0;
}

static void __exit gztun_netdev_exit(void) {
  pr_info("gztun: exiting\n");
  rtnl_link_unregister(&gztun_link_ops);
  free_percpu_ctxs();
}

module_init(gztun_netdev_init);
module_exit(gztun_netdev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuzuki Ishiyama");
MODULE_DESCRIPTION("Generic ZTUN-like virtual network device");
