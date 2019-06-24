
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


x86interpreter	:= X86Interpreter
x86interpreter_class	:= ${SRC_DIR}/$(patsubst %,%.class,$(x86interpreter))
x86interpreter_java  	:= $(patsubst %.class,%.java,$(x86interpreter_class))
x86interpreter_test_class	:= Test${x86interpreter}.class
x86interpreter_test_java 	:= ${TEST_DIR}/$(patsubst %.class,%.java,$(x86interpreter_test_class))
x86interpreter_testor		:= $(patsubst %.class,%,${x86interpreter_test_class})

dep_javafiles1	:= GenericAddress.java Register.java Scalar.java OperandType.java 
dep_javafiles2	:= VSAException.java SymbolicCalculator.java Intruction.java MachineState.java Address.java X86Processor.java
x86interpreter_dep_java		:= $(patsubst %,${SRC_DIR}/operand/%,${dep_javafiles1}) $(patsubst %,${SRC_DIR}/%,${dep_javafiles2}) 
x86interpreter_dep_class	:= $(patsubst %.java,%.class,${x86interpreter_dep_java})


structinfer	:= StructInfer
structinfer_class	:= ${SRC_DIR}/$(patsubst %,%.class,$(structinfer))
structinfer_java  	:= $(patsubst %.class,%.java,$(structinfer_class))
structinfer_test_class	:= Test${structinfer}.class
structinfer_test_java 	:= ${TEST_DIR}/$(patsubst %.class,%.java,$(structinfer_test_class))
structinfer_testor		:= $(patsubst %.class,%,${structinfer_test_class})


help:
	echo "targets: ${calculator} ${smartable} ${x86interpreter} ${structinfer}"


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



${x86interpreter}: ${x86interpreter_class} ${x86interpreter_test_class}
	java -ea ${x86interpreter_testor}

${x86interpreter_class}: ${x86interpreter_java}
	javac -d . $<

${x86interpreter_test_class}: ${x86interpreter_test_java}
	javac -d . $<

${x86interpreter_dep_class} : %.class : %.java
	javac -d . $<


${structinfer}: ${structinfer_class} ${structinfer_test_class}
	java -ea ${structinfer_testor}

${structinfer_class}: ${structinfer_java}
	javac -d . $<

${structinfer_test_class}: ${structinfer_test_java}
	javac -d . $<
