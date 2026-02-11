Need to build an application which must load source code from                                                                                                                                                                      
  the local folder and inspect it for                                                                                                                                                                                                
                                                                                                                                                                                                                                     
                                         
  1. Chaos Engineering pricniples                                                                                                                                                                                                    
  2. OWASP guidelines
  5. SOC2

  Each option can be further configurable based on the compleixy and for cases like SOC2 to compliance clauses.
  Create the system in a manner that's extensible for other types of compliance and audits.


  On a highlevel AI agents for each of the audits must be launched, we can use agent SDK and use OpenAI, Claude or Gemni. Precise skills
  must be created for each agent ie, the SKILLS.md and other attributes
  Agents SDK https://github.com/openai/openai-agents-python

  UI:

  The UI must be https://github.com/ag-ui-protocol/ag-ui based for the user facing UI with intuitive, simple, elegant UI
  The look and feel must be elegant like : https://agentation.dev





  backend can be GO-LANG


  - think
  - plan
  - E2E business logic and tests must be written first and then the code must be written. Then the code must be verified against the busines logic
  - DRY
  - Cyclomatic complexity must be less than 10
  - Code must be optimised even at the assembly level
  - Code must be categorized  for saftey and adhere to ISO 26262
  - 100% test coverage is needed
  - E2E test cases covering business logic must be implemented
  - business logic must be verified after each new code addition/change by running e2e. Make sure to not to modify E2E business logic tests.


  docs/architecture - this folder must have the architeture details

  docs/features/001_feature_name : this folder structure must be defined for feature_name_implemenation_plan.md, rollback_plan.md & implementation_status.md

