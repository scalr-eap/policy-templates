# Check Azure blob storage is not public

package terraform

import input.tfplan as tfplan

deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "azurerm_storage_account"
	r.change.after.allow_blob_public_access == true

	reason := sprintf("%-40s :: Azure storage account blob access must not be PUBLIC", 
	                    [r.address])
}
