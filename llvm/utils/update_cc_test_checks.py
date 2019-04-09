#!/usr/bin/env python3
'''A utility to update LLVM IR CHECK lines in C/C++ FileCheck test files.

Example RUN lines in .c/.cc test files:

// RUN: %clang -emit-llvm -S %s -o - -O2 | FileCheck %s
// RUN: %clangxx -emit-llvm -S %s -o - -O2 | FileCheck -check-prefix=CHECK-A %s

Usage:

% utils/update_cc_test_checks.py --llvm-bin=release/bin test/a.cc
% utils/update_cc_test_checks.py --c-index-test=release/bin/c-index-test \
  --clang=release/bin/clang /tmp/c/a.cc
'''

import argparse
import collections
import distutils.spawn
import os
import shlex
import string
import subprocess
import sys
import re
import tempfile

from UpdateTestChecks import asm, common

ADVERT = '// NOTE: Assertions have been autogenerated by '

CHECK_RE = re.compile(r'^\s*//\s*([^:]+?)(?:-NEXT|-NOT|-DAG|-LABEL)?:')
RUN_LINE_RE = re.compile('^//\s*RUN:\s*(.*)$')

SUBST = {
    '%clang': [],
    '%clang_cc1': ['-cc1'],
    '%clangxx': ['--driver-mode=g++'],
    '%cheri_cc1': ['-cc1', "-triple=cheri-unknown-freebsd"],
    '%cheri_clang': ['-target', 'cheri-unknown-freebsd'],
    '%cheri128_cc1': ['-cc1', "-triple=cheri-unknown-freebsd", "-target-cpu", "cheri128", "-cheri-size", "128"],
    '%cheri256_cc1': ['-cc1', "-triple=cheri-unknown-freebsd", "-target-cpu", "cheri256", "-cheri-size", "256"],
    '%cheri_purecap_clang': ['-target', 'cheri-unknown-freebsd', '-mabi=purecap'],
    '%cheri_purecap_cc1': ['-cc1', "-triple=cheri-unknown-freebsd", "-target-abi", "purecap"],
    '%cheri128_purecap_cc1': ['-cc1', "-triple=cheri-unknown-freebsd", "-target-abi", "purecap", "-target-cpu", "cheri128", "-cheri-size", "128"],
    '%cheri256_purecap_cc1': ['-cc1', "-triple=cheri-unknown-freebsd", "-target-abi", "purecap", "-target-cpu", "cheri256", "-cheri-size", "256"],
}

def get_line2spell_and_mangled(args, clang_args):
  ret = {}
  with tempfile.NamedTemporaryFile() as f:
    # TODO Make c-index-test print mangled names without circumventing through precompiled headers
    c_index_args = [args.c_index_test, '-write-pch', f.name, *clang_args]
    status = subprocess.run(c_index_args,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if status.returncode:
      sys.stderr.write("Failed to run " + " ".join(c_index_args) + "\n")
      sys.stderr.write(status.stdout.decode())
      sys.exit(2)
    output = subprocess.check_output([args.c_index_test,
        '-test-print-mangle', f.name])
    if sys.version_info[0] > 2:
      output = output.decode()

  RE = re.compile(r'^FunctionDecl=(\w+):(\d+):\d+ \(Definition\) \[mangled=([^]]+)\]')
  for line in output.splitlines():
    m = RE.match(line)
    if not m: continue
    spell, line, mangled = m.groups()
    if mangled == '_' + spell:
      # HACK for MacOS (where the mangled name includes an _ for C but the IR won't):
      mangled = spell
    # Note -test-print-mangle does not print file names so if #include is used,
    # the line number may come from an included file.
    ret[int(line)-1] = (spell, mangled)
  if args.verbose:
    for line, func_name in sorted(ret.items()):
      print('line {}: found function {}'.format(line+1, func_name), file=sys.stderr)
  return ret


def config():
  parser = argparse.ArgumentParser(
      description=__doc__,
      formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-v', '--verbose', action='store_true')
  parser.add_argument('--llvm-bin', help='llvm $prefix/bin path')
  parser.add_argument('--clang',
                      help='"clang" executable, defaults to $llvm_bin/clang')
  parser.add_argument('--clang-args',
                      help='Space-separated extra args to clang, e.g. --clang-args=-v')
  parser.add_argument('--c-index-test',
                      help='"c-index-test" executable, defaults to $llvm_bin/c-index-test')
  parser.add_argument(
      '--functions', nargs='+', help='A list of function name regexes. '
      'If specified, update CHECK lines for functions matching at least one regex')
  parser.add_argument(
      '--x86_extra_scrub', action='store_true',
      help='Use more regex for x86 matching to reduce diffs between various subtargets')
  parser.add_argument('tests', nargs='+')
  args = parser.parse_args()
  args.clang_args = shlex.split(args.clang_args or '')

  if args.clang is None:
    if args.llvm_bin is None:
      args.clang = 'clang'
    else:
      args.clang = os.path.join(args.llvm_bin, 'clang')
  if not distutils.spawn.find_executable(args.clang):
    print('Please specify --llvm-bin or --clang', file=sys.stderr)
    sys.exit(1)
  if args.c_index_test is None:
    if args.llvm_bin is None:
      args.c_index_test = 'c-index-test'
    else:
      args.c_index_test = os.path.join(args.llvm_bin, 'c-index-test')
  if not distutils.spawn.find_executable(args.c_index_test):
    print('Please specify --llvm-bin or --c-index-test', file=sys.stderr)
    sys.exit(1)

  return args


def get_function_body(args, filename, clang_args, prefixes, triple_in_cmd, func_dict):
  # TODO Clean up duplication of asm/common build_function_body_dictionary
  # Invoke external tool and extract function bodies.
  raw_tool_output = common.invoke_tool(args.clang, clang_args, filename)
  if '-emit-llvm' in clang_args:
    common.build_function_body_dictionary(
            common.OPT_FUNCTION_RE, common.scrub_body, [],
            raw_tool_output, prefixes, func_dict, args.verbose)
  else:
    print('The clang command line should include -emit-llvm as asm tests '
          'are discouraged in Clang testsuite.', file=sys.stderr)
    sys.exit(1)


def main():
  args = config()
  autogenerated_note = (ADVERT + 'utils/' + os.path.basename(__file__))

  for filename in args.tests:
    with open(filename) as f:
      input_lines = [l.rstrip() for l in f]

    # Extract RUN lines.
    raw_lines = [m.group(1)
                 for m in [RUN_LINE_RE.match(l) for l in input_lines] if m]
    run_lines = [raw_lines[0]] if len(raw_lines) > 0 else []
    for l in raw_lines[1:]:
      if run_lines[-1].endswith("\\"):
        run_lines[-1] = run_lines[-1].rstrip("\\") + " " + l
      else:
        run_lines.append(l)

    if args.verbose:
      print('Found {} RUN lines:'.format(len(run_lines)), file=sys.stderr)
      for l in run_lines:
        print('  RUN: ' + l, file=sys.stderr)

    # Build a list of clang command lines and check prefixes from RUN lines.
    run_list = []
    line2spell_and_mangled_list = collections.defaultdict(list)
    for l in run_lines:
      commands = [cmd.strip() for cmd in l.split('|', 1)]

      triple_in_cmd = None
      m = common.TRIPLE_ARG_RE.search(commands[0])
      if m:
        triple_in_cmd = m.groups()[0]

      # Apply %clang substitution rule, replace %s by `filename`, and append args.clang_args
      clang_args = shlex.split(commands[0])
      if args.verbose:
        print("Before subst:", clang_args)
      if clang_args[0] not in SUBST:
        print('WARNING: Skipping non-clang RUN line: ' + l, file=sys.stderr)
        continue
      clang_args[0:1] = SUBST[clang_args[0]]
      clang_args = [filename if i == '%s' else i for i in clang_args] + args.clang_args
      if args.verbose:
        print("After subst:", clang_args)
      # Extract -check-prefix in FileCheck args
      filecheck_cmd = commands[-1]
      if not filecheck_cmd.startswith('FileCheck ') and not filecheck_cmd.startswith('%cheri_FileCheck '):
        print('WARNING: Skipping non-FileChecked RUN line: ' + l, file=sys.stderr)
        continue
      check_prefixes = [item for m in common.CHECK_PREFIX_RE.finditer(filecheck_cmd)
                               for item in m.group(1).split(',')]
      if not check_prefixes:
        check_prefixes = ['CHECK']
      run_list.append((check_prefixes, clang_args, triple_in_cmd))

    # Strip CHECK lines which are in `prefix_set`, update test file.
    prefix_set = set([prefix for p in run_list for prefix in p[0]])
    input_lines = []
    with open(filename, 'r+') as f:
      for line in f:
        m = CHECK_RE.match(line)
        if not (m and m.group(1) in prefix_set) and line != '//\n':
          input_lines.append(line)
      f.seek(0)
      f.writelines(input_lines)
      f.truncate()

    # Execute clang, generate LLVM IR, and extract functions.
    func_dict = {}
    for p in run_list:
      prefixes = p[0]
      for prefix in prefixes:
        func_dict.update({prefix: dict()})
    for prefixes, clang_args, triple_in_cmd in run_list:
      if args.verbose:
        print('Extracted clang cmd: clang {}'.format(clang_args), file=sys.stderr)
        print('Extracted FileCheck prefixes: {}'.format(prefixes), file=sys.stderr)

      get_function_body(args, filename, clang_args, prefixes, triple_in_cmd, func_dict)

      # Invoke c-index-test to get mapping from start lines to mangled names.
      # Forward all clang args for now.
      for k, v in get_line2spell_and_mangled(args, clang_args).items():
        line2spell_and_mangled_list[k].append(v)

    output_lines = [autogenerated_note]
    for idx, line in enumerate(input_lines):
      # Discard any previous script advertising.
      if line.startswith(ADVERT):
        continue
      if idx in line2spell_and_mangled_list:
        added = set()
        for spell, mangled in line2spell_and_mangled_list[idx]:
          # One line may contain multiple function declarations.
          # Skip if the mangled name has been added before.
          # The line number may come from an included file,
          # we simply require the spelling name to appear on the line
          # to exclude functions from other files.
          if mangled in added or spell not in line:
            continue
          if args.functions is None or any(re.search(regex, spell) for regex in args.functions):
            if added:
              output_lines.append('//')
            added.add(mangled)
            common.add_ir_checks(output_lines, '//', run_list, func_dict, mangled)
      output_lines.append(line.rstrip('\n'))

    # Update the test file.
    with open(filename, 'w') as f:
      for line in output_lines:
        f.write(line + '\n')

  return 0


if __name__ == '__main__':
  sys.exit(main())
