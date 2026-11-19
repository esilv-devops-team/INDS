import { approvalLabels, executionLabels } from '../responseStates'

export default function ResponseStatus({ action }) {
  return (
    <span className="response-states" role="group" aria-label="Approval and gateway execution">
      <span className={'approval ' + action.approval_status}>{approvalLabels[action.approval_status]}</span>
      <span className={'response-execution ' + action.execution_status}>
        {executionLabels[action.execution_status]}
      </span>
    </span>
  )
}
