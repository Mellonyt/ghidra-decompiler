calculator  := symbolicVSA/SymbolicCalculator.class
testor  := TestSymbolicCalculator.class

all: calculator testor
	java -ea TestSymbolicCalculator

calculator: symbolicVSA/SymbolicCalculator.java
	javac -d . $<

testor: unittests/TestSymbolicCalculator.java
	javac -d . $<

