#!/bin/bash

# author - Cory Sabol

# Run from the top directory of the project
javac -cp .:test/:test/junit4-4.12.jar test/CryptoTest.java

java -cp .:test/:test/junit4-4.12.jar:test/hamcrest-core-1.3.jar org.junit.runner.JUnitCore CryptoTest
