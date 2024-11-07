# Device: bigip.maniak.lab (f5.maniak.lab)

## Virtual Servers

| Virtual Server Name | Destination | IP Protocol | Enabled | Status | Pool |
|---------------------|-------------|-------------|---------|--------|------|
| [juiceshop_redirect](#juiceshop_redirect) |  |  |  | unknown | No Pool |
| [juiceshop_vs](#juiceshop_vs) |  |  |  | offline | juiceshop_pool |

## Pool Member Details

### juiceshop_redirect
<a id='juiceshop_redirect'></a>

No pool members associated with this virtual server.

### juiceshop_vs
<a id='juiceshop_vs'></a>

| Pool Name | Member Name | Address | State | Session | Monitor Status | Enabled |
|-----------|-------------|---------|-------|---------|----------------|---------|
| juiceshop_pool | /Common/server01:80 | 172.16.10.114 | down | monitor-enabled |  |  |
| juiceshop_pool | /Common/server01:81 | 172.16.10.114 | down | monitor-enabled |  |  |
| juiceshop_pool | /Common/server01:82 | 172.16.10.114 | down | monitor-enabled |  |  |
| juiceshop_pool | /Common/server01:83 | 172.16.10.114 | down | monitor-enabled |  |  |
| juiceshop_pool | /Common/server01:84 | 172.16.10.114 | down | monitor-enabled |  |  |

