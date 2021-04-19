option(ENABLE_COVERAGE "Enables code coverage" ON)

if (ENABLE_COVERAGE)
    if (NOT DEFINED CODECOV_OUTPUTFILE)
        set( CODECOV_OUTPUTFILE cmake_coverage.output)
    endif (NOT DEFINED CODECOV_OUTPUTFILE)

    if (NOT DEFINED CODECOV_HTMLOUTPUTDIR)
        set(CODECOV_HTMLOUTPUTDIR coverage_results)
    endif (NOT DEFINED CODECOV_HTMLOUTPUTDIR)

    find_program(CODECOV_GCOV gcov)
    find_program(CODECOV_LCOV lcov)
    find_program(CODECOV_GENHTML genhtml)
    add_definitions(--coverage)
    set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} "--coverage")
    add_custom_target(coverage ${CODECOV_LCOV}
        --base-directory .
        --directory ${CMAKE_BINARY_DIR}/src
        --output-file ${CODECOV_OUTPUTFILE}
        --capture
        COMMAND
        genhtml -o ${CODECOV_HTMLOUTPUTDIR} ${CODECOV_OUTPUTFILE})
endif(ENABLE_COVERAGE)
