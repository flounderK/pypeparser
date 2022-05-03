#!/usr/bin/env python3
import argparse


def batch(it, sz):
    length = len(it)
    for i in range(0, length, sz):
        yield it[i:i+sz]


def get_enum_vals(contents, grps=3, getinds=(0, 1)):
    contents = [i for i in contents if i != '']
    enum_vals = []
    for i in batch(contents, grps):
        record = []
        for ind in getinds:
            record.append(i[ind])
        enum_vals.append(record)
    return enum_vals


def class_name_from_filename(filename):
    stripped_filename = filename.replace('.txt', '')
    newclassname = ''
    nextupper = True
    for i in stripped_filename:
        if nextupper:
            nextupper = False
            newclassname += i.upper()
            continue
        if i == '_':
            nextupper = True
            continue
        newclassname += i

    return newclassname


def gen_enum_class_for_file(filename):
    with open(filename, "r") as f:
        contents = f.read().splitlines()

    classname = class_name_from_filename(filename)
    enum_vals = get_enum_vals(contents)
    classbase = 'enum.IntFlag' if any([b.find('x') != -1 for a, b in enum_vals]) \
                else 'enum.IntEnum'

    print(f"class {classname}({classbase}):")

    for a, b in enum_vals:
        print(f"    {a} = {b}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs=argparse.ONE_OR_MORE)
    args = parser.parse_args()
    for i in args.files:
        gen_enum_class_for_file(i)
