set(srcs
    main.cpp
    src/sample_webserver.cpp
    src/perf_measurements.cpp
    src/eval_api.cpp
)

idf_component_register(
    SRCS "${srcs}"
    INCLUDE_DIRS "include"
    EMBED_TXTFILES
        "cert/demo_servercert.pem"
        "cert/demo_prvtkey.pem"
)
