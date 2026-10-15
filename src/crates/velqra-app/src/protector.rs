// SPDX-License-Identifier: GPL-3.0-only
//! The product's `Protector`: Windows DPAPI for the current user (the unsafe code lives in velqra-ipc).

use velqra_core::file_vault::Protector;
use velqra_ipc::DpapiProtector;

#[derive(Clone, Default)]
pub struct UserProtector(DpapiProtector);

impl Protector for UserProtector {
    fn protect(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
        self.0
            .protect(plain, context)
            .map_err(|e| format!("data protection failed: {:?}", e.kind()))
    }

    fn unprotect(&self, blob: &[u8], context: &[u8]) -> Result<Vec<u8>, String> {
        self.0
            .unprotect(blob, context)
            .map_err(|e| format!("data protection failed: {:?}", e.kind()))
    }
}
