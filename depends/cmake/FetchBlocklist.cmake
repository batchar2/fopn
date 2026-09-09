if(NOT EXISTS "${GZ}")
  set(SOURCES
      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt"
      "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
  )

  set(MAX_ATTEMPTS 10)
  set(RETRY_DELAY 5)

  set(combined "${GZ}.txt")
  file(WRITE "${combined}" "")

  foreach(src IN LISTS SOURCES)
    set(part "${GZ}.part")
    set(downloaded FALSE)
    foreach(attempt RANGE 1 ${MAX_ATTEMPTS})
      message(STATUS "[blocklist] downloading ${src} (attempt ${attempt}/${MAX_ATTEMPTS})")
      file(DOWNLOAD "${src}" "${part}" STATUS status TLS_VERIFY ON)
      list(GET status 0 code)
      if(code EQUAL 0)
        set(downloaded TRUE)
        break()
      endif()
      list(GET status 1 msg)
      message(STATUS "[blocklist] attempt ${attempt} failed: ${msg}")
      file(REMOVE "${part}")
      if(NOT attempt EQUAL MAX_ATTEMPTS)
        execute_process(COMMAND ${CMAKE_COMMAND} -E sleep ${RETRY_DELAY})
      endif()
    endforeach()
    if(NOT downloaded)
      file(REMOVE "${part}" "${combined}")
      message(FATAL_ERROR
              "[blocklist] failed ${src} after ${MAX_ATTEMPTS} attempts")
    endif()
    file(READ "${part}" content)
    file(APPEND "${combined}" "${content}")
    file(REMOVE "${part}")
  endforeach()

  file(ARCHIVE_CREATE OUTPUT "${GZ}" PATHS "${combined}"
       FORMAT raw COMPRESSION GZip)
  file(REMOVE "${combined}")
  message(STATUS "[blocklist] saved ${GZ}")
endif()

file(READ "${GZ}" hex HEX)
string(LENGTH "${hex}" hex_len)
math(EXPR num_bytes "${hex_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")

file(WRITE "${OUTPUT}"
"namespace fptn::plugin {
extern const unsigned char ${SYMBOL}[] = {
${bytes}
};
extern const unsigned int ${SYMBOL}Len = ${num_bytes};
}  // namespace fptn::plugin
")
