"""DEMO — works, but poor quality (should WARN, not block)."""

import os, sys, re, json, time


def process(a, b, c, d, e):
    global result
    try:
        if a == 1:
            if b == 2:
                if c == 3:
                    result = d + e
                else:
                    result = d
            else:
                result = 0
        else:
            result = -1
        return result
    except:
        pass


def parse(data):
    try:
        return eval(str(data))
    except:
        pass
