#!/usr/bin/env python3
"""MugVPN's change to openvpn 2.7 for running it without root (privilege separation).

  tools/patch-openvpn-privsep.py <openvpn source dir>

Built with -DMUGVPN_MGMT_TUN, openvpn on macOS does nothing that needs root.
Like openvpn's Android build, it asks its management client instead:

  OPENTUN    give me a tunnel        -> the client answers with a utun descriptor (SCM_RIGHTS)
  IFCONFIG   "local remote-or-netmask mtu topology"
  IFCONFIG6  "addr/bits mtu"
  ROUTE      "network netmask gateway [dev iface]"
  ROUTE6     "network/bits device"
  ROUTEDEL / ROUTE6DEL   the same, to take a route away
  DNSVAR     "name=value", one per variable of openvpn's dns-updown environment, then
  DNSUP / DNSDOWN        "device"

MugVPN's app forwards each request to its root helper, which checks it against the
connection it belongs to and carries it out. Every replacement below must find its
text exactly once: a different openvpn makes this script fail instead of building
something half-patched.
"""
import pathlib
import sys

src = pathlib.Path(sys.argv[1]) / "src" / "openvpn"


def patch(name, old, new, count=1):
    p = src / name
    text = p.read_text()
    n = text.count(old)
    if n != count:
        sys.exit(f"{name}: expected {count} of {old[:60]!r}, found {n}: review MugVPN's privsep patch")
    p.write_text(text.replace(old, new))


ANDROID_OR_US = "#if defined(TARGET_ANDROID) || defined(MUGVPN_MGMT_TUN)"

# --- management: descriptor passing and the NEED-OK control requests -------------
patch("manage.h", "#ifdef TARGET_ANDROID\n    int fdtosend;", ANDROID_OR_US + "\n    int fdtosend;")
patch("manage.h", "#ifdef TARGET_ANDROID\nbool management_android_control(",
      ANDROID_OR_US + "\nbool management_android_control(")
patch("manage.c", "#ifdef TARGET_ANDROID\nstatic ssize_t\nman_send_with_fd(",
      ANDROID_OR_US + "\nstatic ssize_t\nman_send_with_fd(")
patch("manage.c", "#ifdef TARGET_ANDROID\n    int fd;\n    len = man_recv_with_fd(",
      ANDROID_OR_US + "\n    int fd;\n    len = man_recv_with_fd(")
patch("manage.c", "#ifdef TARGET_ANDROID\n        if (man->connection.fdtosend > 0)",
      ANDROID_OR_US + "\n        if (man->connection.fdtosend > 0)")

# --- tun: the device comes from the management client ----------------------------
patch("tun.c", """void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
    /* If dev_node does not start start with utun assume regular tun/tap */""", """void
open_tun(const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt,
         openvpn_net_ctx_t *ctx)
{
#if defined(MUGVPN_MGMT_TUN)
    /* MugVPN: the root helper opens the utun and hands it over. */
    if (!management)
    {
        msg(M_FATAL, "ERROR: MugVPN's openvpn needs its management interface");
    }
    /* One received earlier and never used (0 is "none" here: never stdin). */
    if (management->connection.lastfdreceived > 2)
    {
        close(management->connection.lastfdreceived);
    }
    management->connection.lastfdreceived = -1;
    if (!management_android_control(management, "OPENTUN", dev))
    {
        msg(M_FATAL, "ERROR: MugVPN's helper did not open a tunnel");
    }
    tt->fd = management->connection.lastfdreceived;
    management->connection.lastfdreceived = -1;
    struct stat st;
    char name[IFNAMSIZ] = { 0 };
    socklen_t name_len = sizeof(name);
    if (tt->fd < 3 || fstat(tt->fd, &st) != 0 || !S_ISSOCK(st.st_mode)
        || getsockopt(tt->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &name_len) != 0
        || strncmp(name, "utun", 4) != 0)
    {
        msg(M_FATAL, "ERROR: MugVPN's helper handed over no utun device");
    }
    set_nonblock(tt->fd);
    set_cloexec(tt->fd);
    tt->actual_name = string_alloc(name, NULL);
    tt->backend_driver = DRIVER_UTUN;
    msg(M_INFO, "Opened utun device %s", name);
    return;
#endif
    /* If dev_node does not start start with utun assume regular tun/tap */""")
patch("tun.c", """    if (tt->did_ifconfig_ipv6_setup)
    {
        const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);

        argv_printf(&argv, "%s delete -inet6 %s", ROUTE_PATH, ifconfig_ipv6_local);""", """#if !defined(MUGVPN_MGMT_TUN)
    if (tt->did_ifconfig_ipv6_setup)
#else
    /* MugVPN: the helper removes what it set up. */
    if (0)
#endif
    {
        const char *ifconfig_ipv6_local = print_in6_addr(tt->local_ipv6, 0, &gc);

        argv_printf(&argv, "%s delete -inet6 %s", ROUTE_PATH, ifconfig_ipv6_local);""")

# --- ifconfig ---------------------------------------------------------------------
patch("tun.c", """#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s %s %d %s", ifconfig_local, ifconfig_remote_netmask, tun_mtu,""", """#elif defined(MUGVPN_MGMT_TUN)
    char out[64];

    snprintf(out, sizeof(out), "%s %s %d %s", ifconfig_local, ifconfig_remote_netmask, tun_mtu,
             print_topology(tt->topology));
    if (!management_android_control(management, "IFCONFIG", out))
    {
        msg(M_FATAL, "ERROR: MugVPN's helper refused the tunnel address %s", out);
    }
    (void)tun_p2p;

#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s %s %d %s", ifconfig_local, ifconfig_remote_netmask, tun_mtu,""")
patch("tun.c", """#elif defined(TARGET_ANDROID)
    char out6[64];""", """#elif defined(MUGVPN_MGMT_TUN)
    char out6[64];

    snprintf(out6, sizeof(out6), "%s/%d %d", ifconfig_ipv6_local, tt->netbits_ipv6, tun_mtu);
    if (!management_android_control(management, "IFCONFIG6", out6))
    {
        msg(M_FATAL, "ERROR: MugVPN's helper refused the tunnel address %s", out6);
    }
#elif defined(TARGET_ANDROID)
    char out6[64];""")

# --- routes -----------------------------------------------------------------------
patch("route.c", """#elif defined(TARGET_ANDROID)
    char out[128];

    if (rgi)""", """#elif defined(MUGVPN_MGMT_TUN)
    char out[128];

    if (is_on_link(is_local_route, flags, rgi))
    {
        snprintf(out, sizeof(out), "%s %s %s dev %s", network, netmask, gateway, rgi->iface);
    }
    else
    {
        snprintf(out, sizeof(out), "%s %s %s", network, netmask, gateway);
    }
    msg(D_ROUTE, "MugVPN: route add %s", out);
    bool ret = management_android_control(management, "ROUTE", out);
    if (!ret)
    {
        msg(M_WARN, "MugVPN: the helper refused route %s", out);
    }
    status = ret ? RTA_SUCCESS : RTA_ERROR;

#elif defined(TARGET_ANDROID)
    char out[128];

    if (rgi)""")
patch("route.c", """#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s/%d %s", network, r6->netbits, device);

    status = management_android_control(management, "ROUTE6", out);""", """#elif defined(MUGVPN_MGMT_TUN)
    char out[64];

    snprintf(out, sizeof(out), "%s/%d %s", network, r6->netbits, device);
    msg(D_ROUTE, "MugVPN: route add -inet6 %s", out);
    status = management_android_control(management, "ROUTE6", out) ? RTA_SUCCESS : RTA_ERROR;
    if (status == RTA_ERROR)
    {
        msg(M_WARN, "MugVPN: the helper refused route -inet6 %s", out);
    }

#elif defined(TARGET_ANDROID)
    char out[64];

    snprintf(out, sizeof(out), "%s/%d %s", network, r6->netbits, device);

    status = management_android_control(management, "ROUTE6", out);""")
patch("route.c", """#elif defined(TARGET_DARWIN)

    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf(&argv, "%s delete -cloning -net %s -netmask %s -interface %s", ROUTE_PATH,""", """#elif defined(MUGVPN_MGMT_TUN)
    {
        char out[128];
        if (is_on_link(is_local_route, flags, rgi))
        {
            snprintf(out, sizeof(out), "%s %s %s dev %s", network, netmask, gateway, rgi->iface);
        }
        else
        {
            snprintf(out, sizeof(out), "%s %s %s", network, netmask, gateway);
        }
        management_android_control(management, "ROUTEDEL", out);
    }

#elif defined(TARGET_DARWIN)

    if (is_on_link(is_local_route, flags, rgi))
    {
        argv_printf(&argv, "%s delete -cloning -net %s -netmask %s -interface %s", ROUTE_PATH,""")

patch("route.c", """#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d", ROUTE_PATH, network, r6->netbits);""", """#elif defined(MUGVPN_MGMT_TUN)
    {
        char out[64];
        snprintf(out, sizeof(out), "%s/%d %s", network, r6->netbits, device);
        management_android_control(management, "ROUTE6DEL", out);
    }
    (void)gateway_needed;

#elif defined(TARGET_DARWIN)

    argv_printf(&argv, "%s delete -inet6 %s -prefixlen %d", ROUTE_PATH, network, r6->netbits);""")

# --- DNS: the helper sets it, from openvpn's own dns-updown variables ---------------
patch("dns.c", """static void
run_up_down_command(bool up, struct options *o, const struct tuntap *tt,
                    struct dns_updown_runner_info *updown_runner)
{
    struct dns_options *dns = &o->dns_options;""", """static void
run_up_down_command(bool up, struct options *o, const struct tuntap *tt,
                    struct dns_updown_runner_info *updown_runner)
{
#if defined(MUGVPN_MGMT_TUN)
    {
        struct gc_arena gc = gc_new();
        struct env_set *es = env_set_create(&gc);
        setenv_dns_options(&o->dns_options, es);
        for (struct env_item *e = es->list; e; e = e->next)
        {
            /* The request carries at most USER_PASS_LEN - 1 bytes: never a cut-off value. */
            if (strlen(e->string) >= USER_PASS_LEN - 1)
            {
                msg(M_WARN, "MugVPN: DNS setting too long for the helper, left out: %.40s...", e->string);
                continue;
            }
            management_android_control(management, "DNSVAR", e->string);
        }
        management_android_control(management, up ? "DNSUP" : "DNSDOWN", tt->actual_name);
        gc_free(&gc);
        return;
    }
#endif
    struct dns_options *dns = &o->dns_options;""")
print("==> privsep patch applied to", src)
