#!/bin/bash
export PATH="$HOME/.foundry/bin:$PATH"
export DEPLOY_FACTORY_SALT=0x0000000000000000000000000000000000000000000000000000000000000120
forge test --match-path test/BypassPoC.t.sol -vv
