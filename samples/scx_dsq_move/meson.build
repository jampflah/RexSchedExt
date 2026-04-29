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

scx_dsq_move_clippy = custom_target(
  'scx-dsq-move-clippy',
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

scx_dsq_move_build = custom_target(
  'scx-dsq-move-build',
  output: ['scx_dsq_move'],
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

scx_dsq_move_loader = executable(
  'scx-dsq-move-loader',
  'loader.c',
  build_by_default: true,
  dependencies: [librex_dep, libbpf_dep, kernel_dep],
  pie: true
)

scx_dsq_move_runtest = custom_target(
  'scx_dsq_move_runtest',
  output: ['runtest.py'],
  input: join_paths(meson.current_source_dir(), 'tests/runtest.py'),
  command: ['cp', '@INPUT@', '@OUTPUT@'],
)

scx_dsq_move_expected = custom_target(
  'scx_dsq_move_expected',
  output: ['expected.txt'],
  input: join_paths(meson.current_source_dir(), 'expected.txt'),
  command: ['cp', '@INPUT@', '@OUTPUT@'],
)

runtest_deps += [
  scx_dsq_move_build,
  scx_dsq_move_loader,
  scx_dsq_move_runtest,
  scx_dsq_move_expected,
]

scx_dsq_move_test_env = environment()
scx_dsq_move_test_env.set('SAMPLE_PATH', meson.current_build_dir())
scx_dsq_move_test_env.set('Q_SCRIPT',
  join_paths(meson.project_source_root(), 'scripts/q-script/sanity-test-q')
)
scx_dsq_move_test_env.set('KERNEL_PATH', kbuild_dir)

test('scx_dsq_move_test',
  python3_bin,
  args: [sanity_test_scripts],
  env: scx_dsq_move_test_env,
  depends: runtest_deps,
  is_parallel: false,
  # 60 s is plenty: a green run is ~8 s, and a stalled-scheduler run
  # resolves in ~38 s after the SCX 30 s watchdog kicks. A hard hang
  # then fails fast without burning 3 minutes per attempt.
  timeout: 60,
  workdir: meson.current_build_dir(),
)
