# Jr'er unpxref, naq jr ner tbbq-ybbxvat. Jr ner gur 1%. 
<sub><sup>We only use rot13 for encryption.</sup></sub>

# netsecProject2
Repo for all source and docs related to netsec project2

## TODO:
- Fill out this TODO list
- Write tests

### How to compile
Yes I know the repo is a mess right now, it will be cleaned up eventually.
So, to compile the project, from the command line run `javac Server.java Client.java CryptoUtil.java`

### How to run the programs
Simple open two terminals.
From the root of the project folder in term \#1 run `java Server`
From the root of the project folder in term \#2 run `java Client`
And watch things happen!

### If the programs crash for some reason
Remove the key pairs that were generated and stored in `keys/server/` and `keys/client/`
before running the programs again. (this will be fixed in a later patch)

### run junit test from command line
run `sh test.sh` from the root directory of the project

# THE DREAM TEAM
- Cory Sabol
- Josh Moore
