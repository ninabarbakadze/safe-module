# Withdraw Module

Withdraw module allows accounts not related to the Safe to withdraw a predetermined amount of a specific token using alternative access scheme.

## Approach

- Made myself aware of Safe contracts and Modules
- Looked into and then later borrowed some code from safe-modules repo
- Dusted off my basic knowledge of digital signatures
- Started building out the mvp trying to mostly go with the TDD approach
- After I was done with the main features, I added additional security & sanity checks (i.e. slither, solhint, basic CI)

## Run it locally

```bash
# Clone the repo
git clone https://github.com/ninabarbakadze/safe-module

# Go into the newly cloned repo
cd safe-module

# Install dev dependencies with yarn
yarn

# Install submodule dependencies with forge
forge install

# Compile the smart contracts with forge
forge build

# Run all tests with forge
forge test
```

#### Slither

Install slither, if not already installed.

```bash
pip3 install slither-analyzer
```

Running slither locally requires you to build only a subset of packages:

```bash
forge clean
forge build --build-info --skip tests
slither . --foundry-ignore-compile
```

If you want to ignore a slither warning run:

```bash
slither . --foundry-ignore-compile --triage-mode
```

For triage mode, in which you can choose to ignore warnings which are added to `slither.db.json`

## Deployment

The next thing I'd do would be to actually deploy the Module onto a public testnet. There's certain types of issues you only really start thinking about and finding by interacting with a live system. I'd perform some manual testing, write deployment checks and fork tests that run on top of the deployment.

### Improvements

- Write a more comprehensive test suit including integration, fuzz, invariant and maybe some property based testing with echidna
- Extend Withdraw contract to work with different Safes and tokens
- Should work with multiple signatures depending on the threshold required by the Safe

### Security

As TokenWithdrawModule deals with moving user's funds out of the Safe and signature verification there has to be vigorous testing and audit done in order to avoid common security vulnerabilities associated with such functionality like reentrancy and signature replay attacks.

### Developer Experience 

- Add more GitHub Actions && checks like test coverage reports, etc to ensure that the system is properly verified
- Add audit report and proper documentation to make the module easier to use and integrate
