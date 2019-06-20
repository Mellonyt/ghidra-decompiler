
SRC_DIR     := symbolicVSA
TEST_DIR    := unittests


calculator	:= SymbolicCalculator
calculator_class	:= ${SRC_DIR}/$(patsubst %,%.class,$(calculator))
calculator_java  	:= $(patsubst %.class,%.java,$(calculator_class))
calculator_test_class	:= Test${calculator}.class
calculator_test_java 	:= ${TEST_DIR}/$(patsubst %.class,%.java,$(calculator_test_class))
calculator_testor		:= $(patsubst %.class,%,${calculator_test_class})


smartable	:= SMARTable
smartable_class	:= ${SRC_DIR}/$(patsubst %,%.class,$(smartable))
smartable_java  	:= $(patsubst %.class,%.java,$(smartable_class))
smartable_test_class	:= Test${smartable}.class
smartable_test_java 	:= ${TEST_DIR}/$(patsubst %.class,%.java,$(smartable_test_class))
smartable_testor		:= $(patsubst %.class,%,${smartable_test_class})


help:
	echo "targets: ${calculator} ${smartable}"



${calculator}: ${calculator_class} ${calculator_test_class}
	java -ea ${calculator_testor}

${calculator_class}: ${calculator_java}
	javac -d . $<

${calculator_test_class}: ${calculator_test_java}
	javac -d . $<



${smartable}: ${smartable_class} ${smartable_test_class}
	java -ea ${smartable_testor}

${smartable_class}: ${smartable_java}
	javac -d . $<

${smartable_test_class}: ${smartable_test_java}
	javac -d . $<