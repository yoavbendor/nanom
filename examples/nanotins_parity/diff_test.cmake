# Run EXE with ARGS (a ;-separated list), capture stdout, compare to GOLDEN.
execute_process(
  COMMAND "${EXE}" ${ARGS}
  OUTPUT_VARIABLE actual
  RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "${EXE} exited ${rc}")
endif()
file(READ "${GOLDEN}" expected)
if(NOT actual STREQUAL expected)
  message(FATAL_ERROR "output does not match golden ${GOLDEN}")
endif()
