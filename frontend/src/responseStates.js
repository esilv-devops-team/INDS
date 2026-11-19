export const approvalLabels = {
  pending: 'Pending approval',
  approved: 'Approved',
  rejected: 'Rejected',
  cancelled: 'Cancelled',
}

export const executionLabels = {
  not_applied: 'Not applied',
  applying: 'Applying',
  active: 'Reported active',
  removing: 'Removal in progress',
  removed: 'Removed',
  failed: 'Execution failed',
  unknown: 'Execution unknown',
}

export function actionName(action) {
  return action.action_type === 'block' ? 'Block device' : 'Rate limit'
}
