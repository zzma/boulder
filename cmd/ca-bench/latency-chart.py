#!/usr/bin/env python2.7
import matplotlib
import matplotlib.pyplot as plt
import datetime
import json
import pandas
import argparse
import os

matplotlib.style.use('ggplot')

def create_latency_meta(data, frames):
    cm = []
    crm = []
    for f in frames:
        if data.get(f[0], False):
            calls = pandas.DataFrame(data[f[0]])
            calls['x'] = pandas.to_datetime(calls['x']).astype(datetime.datetime)
            calls['y'] = calls['y'].divide(1000000)
            calls = calls.set_index('x')
            call_rate = calls.resample('S', how='count')
            # call_rate['y'] = call_rate['y'].divide(5)
            cm.append([calls, f[0], f[1], f[2]])
            crm.append([call_rate, f[0], f[1]])
    return cm, crm

def plot_meta(c_meta, cr_meta, sent, hist, title):
    ax1 = plt.subplot(312)
    for m in cr_meta:
        ax1.plot_date(m[0].index, m[0]['y'], '-', label=m[1], color=m[2])

    ax2 = plt.subplot(313, sharex=ax1)
    maxLatency = 0
    for m in c_meta:
        ax2.plot_date(m[0].index, m[0]['y'], label=m[1], color=m[2], marker=m[3])
        thisMax = max(m[0]['y'])
        maxLatency = thisMax if thisMax > maxLatency else maxLatency

    ax3 = plt.subplot(311)
    ax3.plot(range(len(hist['x'])), [v/1000000 for v in hist['valueY']], label='value', color='green')
    ax4 = ax3.twinx()
    cY = [y-hist['countY'][i-1] for i, y in enumerate(hist['countY']) if i > 0]
    cY = [hist['countY'][0]] + cY
    ax4.plot(range(len(hist['x'])), cY, '-', label='count', color='blue')

    ax1.axhline(sent, color='black', linestyle='--', label='sent')
    ax2.axhline(10000, color='red', linestyle='--', label='hard maximum')
    ax3.axhline(10000, linestyle='--', label='hard maximum', color='red')

    ax3.set_xticks(range(len(hist['x'])))
    ax3.set_xticklabels([str(x)[0:6] for x in hist['x']])

    ax3.set_xlabel('Percentile')

    ax1.set_ylabel("Finished calls rate (/s)")
    ax2.set_ylabel("Call latency (ms)")
    ax3.set_ylabel('Value (ms)')
    ax4.set_ylabel('Count')

    # ax1.set_ylim(0, sent+(sent*0.25))
    ax2.set_ylim(0, maxLatency+(maxLatency*0.1))
    maxHistLatency = max([v/1000000 for v in hist['valueY']])
    ax3.set_ylim(0, maxHistLatency+(maxHistLatency*0.1))

    ax1.legend(ncol=4, bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0.)
    ax2.legend(ncol=4, bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0., numpoints=1)
    handles, labels = ax4.get_legend_handles_labels()
    moreHandles, moreLabels = ax3.get_legend_handles_labels()
    ax3.legend(moreHandles+handles, moreLabels+labels, ncol=4, bbox_to_anchor=(0., 1.02, 1., .102), loc=3, mode="expand", borderaxespad=0.)

    ax1.grid(False)
    ax2.grid(False)
    ax3.grid(False)
    ax4.grid(False)

    plt.subplots_adjust(hspace=0.35)
    plt.suptitle(title, fontsize=16)

parser = argparse.ArgumentParser()
parser.add_argument('chartData', type=str, help='Path to file containing JSON chart output from ca-bench')
parser.add_argument('--outputPrefix', type=str, help='Prefix for chart filenames')
parser.add_argument('--outputDir', type=str, help='Path to directory to save charts in')
args = parser.parse_args()

with open(args.chartData) as data_file:
    stuff = json.load(data_file)

conf = [
    ['good', 'green', '+'],
    ['error', 'red', 'x'],
    ['timeout', 'orange', 'x']
]

matplotlib.rcParams['figure.figsize'] = 18, 12

if stuff.get('issuance', False):
    call_stuff, rate_stuff = create_latency_meta(stuff['issuance'], conf)
    plot_meta(call_stuff, rate_stuff, stuff.get('issuanceSent', 0), stuff.get('issuanceLatency', False), 'IssueCertificate overview')
    chartPath = "issuance.png"
    if args.outputPrefix != None:
        chartPath = args.outputPrefix+'-'+chartPath
    if args.outputDir != None:
        chartPath = os.path.join(args.outputDir, chartPath)
    plt.savefig(chartPath, bbox_inches='tight')

plt.close()

if stuff.get('ocsp', False):
    call_stuff, rate_stuff = create_latency_meta(stuff['ocsp'], conf)
    plot_meta(call_stuff, rate_stuff, stuff.get('ocspSent', 0), stuff.get('ocspLatency', False), 'GenerateOCSP overview')
    chartPath = "ocsp.png"
    if args.outputPrefix != None:
        chartPath = args.outputPrefix+'-'+chartPath
    if args.outputDir != None:
        chartPath = os.path.join(args.outputDir, chartPath)
    plt.savefig(chartPath, bbox_inches='tight')
