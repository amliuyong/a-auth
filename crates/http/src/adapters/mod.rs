//! 端口的适配器实现:内存(本地/测试)+ AWS(真机,`aws` feature)。

pub mod memory;
pub mod memory_attribute_namespaces;
pub mod memory_federation_attributes;

#[cfg(feature = "aws")]
pub mod aws;
