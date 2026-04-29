build_dir = run_command(
  realpath,
  '--relative-to',
  meson.current_source_dir(),
  meson.current_build_dir(),
  capture: true,
  check: true
).stdout().strip()

env = environment()
env.prepend('PATH', rust_bin)
env.set('LINUX_OBJ', kbuild_dir)
env.set('LINUX_SRC', join_paths(meson.project_source_root(), './linux'))
env.set('CARGO_TARGET_DIR', join_paths(build_dir, 'target'))

scx_vtime_clippy = custom_target(
  'scx-vtime-clippy',
  output: ['target'],
  command: [
    cargo_wrapper, rust_bin, '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'clippy', '-qr'
  ],
  env: env,
  console: false,
  build_by_default: true
)

scx_vtime_build = custom_target(
  'scx-vtime-build',
  output: ['scx_vtime'],
  command: [
    cargo_wrapper, rust_bin, '-Z',
    'unstable-options',
    '-C', meson.current_source_dir(),
    'rustc', '-qr', '--',
    '-Cenable_rex'
  ],
  depends: sample_clippy,
  env: env,
  console: false,
  build_by_default: true
)

scx_vtime_loader = executable(
  'scx-vtime-loader',
  'loader.c',
  build_by_default: true,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  pie: true
)

scx_vtime_runtest = custom_target(
  'scx_vtime_runtest',
  output: ['runtest.py'],
  input: join_paths(meson.current_source_dir(), 'tests/runtest.py'),
  command: ['cp', '@INPUT@', '@OUTPUT@'],
)

scx_vtime_expected = custom_target(
  'scx_vtime_expected',
  output: ['expected.txt'],
  input: join_paths(meson.current_source_dir(), 'expected.txt'),
  command: ['cp', '@INPUT@', '@OUTPUT@'],
)

runtest_deps += [
  scx_vtime_build,
  scx_vtime_loader,
  scx_vtime_runtest,
  scx_vtime_expected,
]

scx_vtime_test_env = environment()
scx_vtime_test_env.set('SAMPLE_PATH', meson.current_build_dir())
scx_vtime_test_env.set('Q_SCRIPT',
  join_paths(meson.project_source_root(), 'scripts/q-script/sanity-test-q')
)
scx_vtime_test_env.set('KERNEL_PATH', kbuild_dir)

test('scx_vtime_test',
  python3_bin,
  args: [sanity_test_scripts],
  env: scx_vtime_test_env,
  depends: runtest_deps,
  is_parallel: false,
  timeout: 180,
  workdir: meson.current_build_dir(),
)
