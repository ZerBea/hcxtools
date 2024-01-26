project(
  'hcxtools',
  'c',
  version: '6.3.2',
  default_options: ['warning_level=3'],
)

vyear = 2024

if true
  vtag = meson.project_version()
else
  gcmd = run_command('git describe --tags')
  if gcmd.returncode() == 0
    vtag = gcmd.stdout()
  else
    vtag = meson.project_version()
  endif
endif

add_project_arguments('-DVERSION_TAG="@0@"'.format(vtag), language: 'c')
add_project_arguments('-DVERSION_YEAR="@0@"'.format(vyear), language: 'c')

cc = meson.get_compiler('c')

curl_dep = dependency('libcurl', required: get_option('curl'))
openssl_dep = dependency('openssl', required: get_option('openssl'))
winsock_dep = cc.find_library('ws2_32', required: host_machine.system() == 'windows')
zlib_dep = dependency('zlib', required: get_option('zlib'))
if zlib_dep.found()
  add_project_arguments('-DWANTZLIB', language: 'c')
endif

tools = {
  'hcxeiutool': [],
  'hcxwltool': [],
  'hcxhash2cap': winsock_dep,
}

if curl_dep.found()
  tools += {'wlancap2wpasec': curl_dep}
  if host_machine.system() != 'windows'
    tools += {'whoismac': curl_dep}
  endif
endif

if openssl_dep.found()
  tools += {
    'hcxpcapngtool': [openssl_dep, winsock_dep, zlib_dep],
    'hcxpsktool': openssl_dep,
    'hcxpmktool': [openssl_dep, winsock_dep],
  }
  if host_machine.system() != 'windows' and curl_dep.found()
    tools += {'hcxhashtool': [curl_dep, openssl_dep]}
  endif
endif

foreach t, d : tools
  executable(
    t,
    '@0@.c'.format(t),
    dependencies: d,
    install: true,
  )
endforeach
