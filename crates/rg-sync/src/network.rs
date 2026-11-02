//! Railgun V2 deployments (shared-models `network-config.ts`).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub name: &'static str,
    pub chain_id: u64,
    pub proxy: &'static str,
    pub deployment_block: u64,
    pub wrapped_token: &'static str,
    /// Indexer with every leaf, legacy ones included.
    pub squid: Option<&'static str>,
    /// Blocks refetched on every sync, in case they were reorged.
    pub reorg_window: u64,
}

impl Network {
    pub const SEPOLIA: Network = Network {
        name: "sepolia",
        chain_id: 11_155_111,
        proxy: "0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea",
        deployment_block: 5_784_866,
        wrapped_token: "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14",
        squid: None,
        reorg_window: 64,
    };
    pub const ETHEREUM: Network = Network {
        name: "ethereum",
        chain_id: 1,
        proxy: "0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9",
        deployment_block: 14_737_691,
        wrapped_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
        squid: Some("https://rail-squid.squids.live/squid-railgun-ethereum-v2/graphql"),
        reorg_window: 64,
    };
    pub const ARBITRUM: Network = Network {
        name: "arbitrum",
        chain_id: 42_161,
        proxy: "0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9",
        deployment_block: 56_109_834,
        wrapped_token: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
        squid: Some("https://rail-squid.squids.live/squid-railgun-arbitrum-v2/graphql"),
        reorg_window: 2_400,
    };

    pub fn by_name(name: &str) -> Option<Network> {
        [Self::SEPOLIA, Self::ETHEREUM, Self::ARBITRUM]
            .into_iter()
            .find(|n| n.name == name)
    }
}
