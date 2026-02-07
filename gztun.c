#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>

#define DRV_NAME "gztun"

struct gztun_struct {
  struct net_device *redirect_dev;
  netdevice_tracker tracker;
};

static inline void free_gztun_struct(struct gztun_struct *gztun) {
  if (gztun->redirect_dev) {
    netdev_put(gztun->redirect_dev, &gztun->tracker);
    gztun->redirect_dev = NULL;
  }
}

static netdev_tx_t gztun_start_xmit(struct sk_buff *skb, struct net_device *dev) {
  struct gztun_struct *gztun;

  pr_info("gztun: start_xmit called, len=%u\n", skb->len);
  pr_info("gztun: skb->dev name=%s\n", skb->dev->name);

  gztun = netdev_priv(dev);
  skb->dev = gztun->redirect_dev;
  dev_queue_xmit(skb);

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

static int gztun_newlink(struct net_device *dev, struct rtnl_newlink_params *params, struct netlink_ext_ack *extack) {
  pr_info("gztun: newlink called for device %s\n", dev->name);

  struct gztun_struct *gztun;
  struct nlattr **tb;
  struct net_device *link_dev;
  u32 ifindex;
  int err;

  gztun = netdev_priv(dev);
  gztun->redirect_dev = NULL;
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

  err = register_netdevice(dev);
  if (err) {
    pr_err("gztun: register_netdev failed: %d\n", err);
    free_gztun_struct(gztun);
  }
  return err;
}

static void gztun_dellink(struct net_device *dev, struct list_head *head) {
  struct gztun_struct *gztun = netdev_priv(dev);
  free_gztun_struct(gztun);
  unregister_netdev(dev);
}

static struct rtnl_link_ops gztun_link_ops = {
    .kind = DRV_NAME,
    .setup = gztun_setup,
    .validate = gztun_validate,
    .newlink = gztun_newlink,
    .dellink = gztun_dellink,
    .priv_size = sizeof(struct gztun_struct),
};

static int __init gztun_netdev_init(void) {
  pr_info("gztun: initializing\n");

  int err;

  err = rtnl_link_register(&gztun_link_ops);
  if (err < 0) {
    pr_err("gztun: failed to register rtnl link ops\n");
    return -1;
  }

  return 0;
}

static void __exit gztun_netdev_exit(void) {
  pr_info("gztun: exiting\n");
  rtnl_link_unregister(&gztun_link_ops);
}

module_init(gztun_netdev_init);
module_exit(gztun_netdev_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuzuki Ishiyama");
MODULE_DESCRIPTION("Generic ZTUN-like virtual network device");
