//! Where a replica goes in the customer's VNet, worked out from `az network vnet` JSON: the
//! subnet `seal` (reused when it is delegated to container groups, else a new /27 in free
//! address space) and its NAT gateway (the subnet's own, one another subnet of the VNet uses,
//! or a new `seal-nat`). Pure: `mod.rs` runs the commands.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;

use anyhow::{anyhow, bail};
use serde_json::Value;

use super::DELEGATION;

/// The subnet replicas get when none is named.
pub const SUBNET: &str = "seal";

/// An IPv4 prefix, its host bits cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    base: u32,
    len: u8,
}

impl Cidr {
    /// `a.b.c.d/n`; `None` for IPv6 and anything else.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, len) = s.trim().split_once('/')?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        let len: u8 = len.parse().ok().filter(|l| *l <= 32)?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Some(Self { base: u32::from(addr) & mask, len })
    }

    fn start(self) -> u64 {
        u64::from(self.base)
    }

    /// One past the last address.
    fn end(self) -> u64 {
        self.start() + (1u64 << (32 - self.len))
    }

    fn overlaps(self, other: Self) -> bool {
        self.start() < other.end() && other.start() < self.end()
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.len)
    }
}

/// The first `/len` inside `space` that overlaps nothing in `used`.
pub fn free_block(space: &[Cidr], used: &[Cidr], len: u8) -> Option<Cidr> {
    let size = 1u64 << (32 - len);
    for range in space.iter().filter(|r| r.len <= len) {
        let mut at = range.start();
        while at + size <= range.end() {
            let block = Cidr { base: at as u32, len };
            match used.iter().filter(|u| u.overlaps(block)).map(|u| u.end()).max() {
                None => return Some(block),
                Some(end) => at = end.div_ceil(size) * size,
            }
        }
    }
    None
}

/// A VNet as `az network vnet show|list` prints it.
#[derive(Debug)]
pub struct Vnet {
    pub id: String,
    pub name: String,
    pub resource_group: String,
    pub location: String,
    /// Its IPv4 address space.
    pub space: Vec<Cidr>,
    pub subnets: Vec<Value>,
}

impl Vnet {
    pub fn parse(v: &Value) -> anyhow::Result<Self> {
        let field = |key: &str| v[key].as_str().map(str::to_owned).ok_or_else(|| anyhow!("the VNet has no {key}"));
        let id = field("id")?;
        let resource_group = match v["resourceGroup"].as_str() {
            Some(rg) => rg.to_owned(),
            None => segment(&id, "resourceGroups").ok_or_else(|| anyhow!("{id} names no resource group"))?.to_owned(),
        };
        let space = strings(&v["addressSpace"]["addressPrefixes"]).filter_map(Cidr::parse).collect();
        let subnets = v["subnets"].as_array().cloned().unwrap_or_default();
        Ok(Self { name: field("name")?, location: field("location")?, id, resource_group, space, subnets })
    }

    /// The subnet named `name` (Azure names ignore case).
    pub fn subnet(&self, name: &str) -> Option<&Value> {
        self.subnets.iter().find(|s| s["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name)))
    }

    /// `name (resource group, location, address space)`, for choosing one.
    pub fn about(&self) -> String {
        let space: Vec<String> = self.space.iter().map(Cidr::to_string).collect();
        format!("{}, {}, {}", self.resource_group, self.location, space.join(" "))
    }
}

fn strings(v: &Value) -> impl Iterator<Item = &str> {
    v.as_array().into_iter().flatten().filter_map(Value::as_str)
}

/// The path segment after `key` in a resource id.
fn segment<'a>(id: &'a str, key: &str) -> Option<&'a str> {
    let mut parts = id.split('/');
    parts.by_ref().find(|p| p.eq_ignore_ascii_case(key))?;
    parts.next().filter(|p| !p.is_empty())
}

/// A resource id's last segment: its name.
pub fn leaf(id: &str) -> &str {
    id.rsplit('/').next().unwrap_or(id)
}

pub fn delegated(subnet: &Value) -> bool {
    subnet["delegations"].as_array().is_some_and(|ds| ds.iter().any(|d| d["serviceName"] == DELEGATION))
}

fn nat_gateway(subnet: &Value) -> Option<&str> {
    subnet["natGateway"]["id"].as_str()
}

/// The subnet's address prefixes (`addressPrefix` or `addressPrefixes`).
fn prefixes(subnet: &Value) -> impl Iterator<Item = Cidr> + '_ {
    subnet["addressPrefix"].as_str().into_iter().chain(strings(&subnet["addressPrefixes"])).filter_map(Cidr::parse)
}

/// The VNet named by `--vnet` or `--subnet`, and the subnet `--subnet` names.
#[derive(Debug, PartialEq, Eq)]
pub struct Wanted {
    /// A VNet name or resource id; `None`: ask.
    pub vnet: Option<String>,
    pub subnet: Option<String>,
}

/// `--vnet NAME|ID` and `--subnet [VNET/]SUBNET|ID`: a subnet id or `VNET/` names its VNet.
pub fn wanted(vnet: Option<&str>, subnet: Option<&str>) -> anyhow::Result<Wanted> {
    let Some(subnet) = subnet else {
        return Ok(Wanted { vnet: vnet.map(str::to_owned), subnet: None });
    };
    let (from_subnet, name) = if subnet.starts_with("/subscriptions/") {
        let at =
            subnet.to_ascii_lowercase().rfind("/subnets/").ok_or_else(|| anyhow!("{subnet} is not a subnet id"))?;
        (Some(&subnet[..at]), &subnet[at + "/subnets/".len()..])
    } else {
        match subnet.split_once('/') {
            None => (None, subnet),
            Some((v, s)) => (Some(v), s),
        }
    };
    if name.is_empty() || name.contains('/') || from_subnet.is_some_and(str::is_empty) {
        bail!("--subnet takes SUBNET (in --vnet's VNet), VNET/SUBNET or a subnet resource id");
    }
    let vnet = match (vnet, from_subnet) {
        (Some(v), Some(f)) if !(v.eq_ignore_ascii_case(f) || v.eq_ignore_ascii_case(leaf(f))) => {
            bail!("--subnet {subnet} is not in --vnet {v}")
        }
        (v, f) => f.or(v).map(str::to_owned),
    };
    Ok(Wanted { vnet, subnet: Some(name.to_owned()) })
}

/// The one VNet of `vnets` called `name`.
pub fn named(vnets: Vec<Vnet>, name: &str) -> anyhow::Result<Vnet> {
    let mut found: Vec<Vnet> = vnets.into_iter().filter(|v| v.name.eq_ignore_ascii_case(name)).collect();
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!(
            "the subscription has no VNet {name} (`az account show` names the subscription, `az account set -s` \
             switches it)"
        ),
        _ => bail!("several VNets are named {name}: pass --vnet with the resource id of the one your apps run in"),
    }
}

/// The subnet replicas go in.
#[derive(Debug, PartialEq, Eq)]
pub enum Subnet {
    /// `seal`, already delegated (its id).
    Existing(String),
    /// A new `seal` with this prefix.
    Create(Cidr),
}

/// The NAT gateway that subnet egresses through.
#[derive(Debug, PartialEq, Eq)]
pub enum Nat {
    /// The subnet's own.
    Attached(String),
    /// One another subnet of the VNet uses, attached to this one too.
    Shared(String),
    /// None in the VNet: `seal-nat` is created.
    Create,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub subnet: Subnet,
    pub nat: Nat,
}

/// What `vnet` needs for a replica.
pub fn plan(vnet: &Vnet) -> anyhow::Result<Plan> {
    let shared = || {
        let used: BTreeSet<&str> = vnet.subnets.iter().filter_map(nat_gateway).collect();
        used.first().map_or(Nat::Create, |id| Nat::Shared((*id).to_owned()))
    };
    if let Some(subnet) = vnet.subnet(SUBNET) {
        let id = subnet["id"].as_str().ok_or_else(|| anyhow!("subnet {SUBNET} of {} has no id", vnet.name))?;
        if !delegated(subnet) {
            bail!(
                "subnet {SUBNET} in {} is not delegated to container groups: \
                 az network vnet subnet update --ids {id} --delegations {DELEGATION}, or pass --subnet",
                vnet.name
            );
        }
        let nat = nat_gateway(subnet).map_or_else(shared, |n| Nat::Attached(n.to_owned()));
        return Ok(Plan { subnet: Subnet::Existing(id.to_owned()), nat });
    }
    let used: Vec<Cidr> = vnet.subnets.iter().flat_map(prefixes).collect();
    let Some(free) = free_block(&vnet.space, &used, 27) else {
        let space: Vec<String> = vnet.space.iter().map(Cidr::to_string).collect();
        bail!(
            "{} has no free /27 for subnet {SUBNET} in its address space ({}): add a range \
             (az network vnet update --ids {} --add addressSpace.addressPrefixes PREFIX), or pass --subnet",
            vnet.name,
            space.join(" "),
            vnet.id
        );
    };
    Ok(Plan { subnet: Subnet::Create(free), nat: shared() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter().map(|c| Cidr::parse(c).unwrap()).collect()
    }

    fn free(space: &[&str], used: &[&str]) -> Option<String> {
        free_block(&cidrs(space), &cidrs(used), 27).map(|c| c.to_string())
    }

    #[test]
    fn prefixes_parse_ipv4_only() {
        assert_eq!(Cidr::parse("10.1.2.3/16").unwrap().to_string(), "10.1.0.0/16");
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().to_string(), "0.0.0.0/0");
        assert!(Cidr::parse("fd00::/64").is_none());
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("10.0.0.0").is_none());
    }

    #[test]
    fn the_first_free_slash_27_is_taken() {
        assert_eq!(free(&["10.20.0.0/16"], &[]).unwrap(), "10.20.0.0/27");
        assert_eq!(free(&["10.20.0.0/16"], &["10.20.0.0/24", "10.20.1.0/24"]).unwrap(), "10.20.2.0/27");
        // A smaller subnet still takes the whole /27 it sits in.
        assert_eq!(
            free(&["10.20.0.0/16"], &["10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/28"]).unwrap(),
            "10.20.2.32/27"
        );
        // A larger one, unaligned to the walk, is skipped past.
        assert_eq!(
            free(&["10.0.0.0/22"], &["10.0.0.32/27", "10.0.0.0/27", "10.0.0.64/26", "10.0.0.128/25"]).unwrap(),
            "10.0.1.0/27"
        );
        // A full range moves on to the next; a range smaller than /27 is no use.
        assert_eq!(
            free(&["10.0.0.0/27", "10.9.0.0/28", "192.168.0.0/24"], &["10.0.0.0/27"]).unwrap(),
            "192.168.0.0/27"
        );
        assert_eq!(free(&["10.0.0.0/26"], &["10.0.0.0/27", "10.0.0.32/27"]), None);
        assert_eq!(free(&["10.0.0.0/28"], &[]), None);
        assert_eq!(free(&["255.255.255.224/27"], &[]).unwrap(), "255.255.255.224/27");
    }

    fn vnet(subnets: Value) -> Vnet {
        Vnet::parse(&json!({
            "id": "/subscriptions/s/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/app-vnet",
            "name": "app-vnet",
            "location": "eastus",
            "addressSpace": {"addressPrefixes": ["10.20.0.0/16", "fd00::/48"]},
            "subnets": subnets,
        }))
        .unwrap()
    }

    const NAT_ID: &str = "/subscriptions/s/resourceGroups/net/providers/Microsoft.Network/natGateways/app-nat";

    #[test]
    fn vnets_parse_from_az_json() {
        let v = vnet(json!([]));
        assert_eq!((v.name.as_str(), v.resource_group.as_str(), v.location.as_str()), ("app-vnet", "net", "eastus"));
        assert_eq!(v.space, cidrs(&["10.20.0.0/16"]));
        assert_eq!(v.about(), "net, eastus, 10.20.0.0/16");
    }

    #[test]
    fn a_delegated_seal_subnet_is_reused() {
        let id = "/subscriptions/s/.../subnets/seal";
        let with_nat = vnet(json!([{
            "name": "Seal", "id": id, "addressPrefix": "10.20.9.0/27",
            "delegations": [{"serviceName": DELEGATION}], "natGateway": {"id": NAT_ID},
        }]));
        assert_eq!(
            plan(&with_nat).unwrap(),
            Plan { subnet: Subnet::Existing(id.into()), nat: Nat::Attached(NAT_ID.into()) }
        );

        let without = vnet(json!([
            {"name": "apps", "id": "/x/apps", "addressPrefix": "10.20.0.0/24", "natGateway": {"id": NAT_ID}},
            {"name": "seal", "id": id, "addressPrefix": "10.20.9.0/27", "delegations": [{"serviceName": DELEGATION}]},
        ]));
        assert_eq!(
            plan(&without).unwrap(),
            Plan { subnet: Subnet::Existing(id.into()), nat: Nat::Shared(NAT_ID.into()) }
        );

        let undelegated = vnet(json!([{"name": "seal", "id": id, "addressPrefix": "10.20.9.0/27", "delegations": []}]));
        assert!(plan(&undelegated).unwrap_err().to_string().contains("--delegations"));
    }

    #[test]
    fn otherwise_a_seal_subnet_is_created_in_free_space() {
        let apps = json!({"name": "apps", "id": "/x/apps", "addressPrefixes": ["10.20.0.0/24"]});
        let db = json!({"name": "db", "id": "/x/db", "addressPrefix": "10.20.1.0/24", "natGateway": {"id": NAT_ID}});
        assert_eq!(
            plan(&vnet(json!([apps]))).unwrap(),
            Plan { subnet: Subnet::Create(Cidr::parse("10.20.1.0/27").unwrap()), nat: Nat::Create }
        );
        assert_eq!(
            plan(&vnet(json!([apps, db]))).unwrap(),
            Plan { subnet: Subnet::Create(Cidr::parse("10.20.2.0/27").unwrap()), nat: Nat::Shared(NAT_ID.into()) }
        );
        let full = vnet(json!([{"name": "all", "id": "/x/all", "addressPrefix": "10.20.0.0/16"}]));
        assert!(plan(&full).unwrap_err().to_string().contains("no free /27"));
    }

    #[test]
    fn the_vnet_comes_from_vnet_or_subnet() {
        let w = |v: Option<&str>, s: Option<&str>| wanted(v, s);
        let both = |v: Option<&str>, s: Option<&str>| Wanted { vnet: v.map(Into::into), subnet: s.map(Into::into) };
        assert_eq!(w(None, None).unwrap(), both(None, None));
        assert_eq!(w(Some("app-vnet"), None).unwrap(), both(Some("app-vnet"), None));
        assert_eq!(w(Some("app-vnet"), Some("seal")).unwrap(), both(Some("app-vnet"), Some("seal")));
        assert_eq!(w(None, Some("app-vnet/seal")).unwrap(), both(Some("app-vnet"), Some("seal")));
        let vnet_id = "/subscriptions/s/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/app-vnet";
        let subnet_id = format!("{vnet_id}/subnets/seal");
        assert_eq!(w(None, Some(&subnet_id)).unwrap(), both(Some(vnet_id), Some("seal")));
        assert_eq!(w(Some("app-vnet"), Some(&subnet_id)).unwrap(), both(Some(vnet_id), Some("seal")));
        assert!(w(Some("other"), Some("app-vnet/seal")).unwrap_err().to_string().contains("not in --vnet"));
        assert!(w(None, Some("a/b/c")).is_err());
        assert!(w(None, Some("/seal")).is_err());
    }

    #[test]
    fn a_vnet_name_must_be_unambiguous() {
        let named_in = |rg: &str| {
            Vnet::parse(&json!({
                "id": format!("/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/app"),
                "name": "app", "location": "eastus",
            }))
            .unwrap()
        };
        assert_eq!(named(vec![named_in("a")], "APP").unwrap().resource_group, "a");
        assert!(named(vec![named_in("a")], "other").unwrap_err().to_string().contains("no VNet other"));
        assert!(named(vec![named_in("a"), named_in("b")], "app").unwrap_err().to_string().contains("resource id"));
    }
}
