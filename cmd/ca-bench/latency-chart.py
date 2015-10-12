#!/usr/bin/env python2.7
import matplotlib
import matplotlib.pyplot as plt
import datetime
import json
import pandas

matplotlib.style.use('ggplot')

def create_latency_meta(data, frames):
    cm = []
    crm = []
    for f in frames:
        if data.get(f[0], False):
            calls = pandas.DataFrame(data[f[0]])
            calls['x'] = pandas.to_datetime(calls['x'])
            calls['y'] = calls['y'].divide(1000000)
            calls = calls.set_index('x')
            call_rate = calls.resample('S', how='count')
            # call_rate['y'] = call_rate['y'].divide(5)
            cm.append([calls, f[0], f[1], f[2]])
            crm.append([call_rate, f[0], f[1]])
    return cm, crm

def plot_meta(c_meta, cr_meta, sent, hist):
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
    ax3.plot(range(len(hist['x'])), hist['valueY'], label='value', color='green')
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

    ax2.set_ylim(0, maxLatency+(maxLatency*0.1))
    maxHistLatency = max(hist['valueY'])
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

with open('/home/roland/Dropbox/code/go/src/github.com/letsencrypt/boulder/chart.json') as data_file:
    stuff = json.load(data_file)

conf = [
            ['good', 'green', '+'],
            ['error', 'red', 'x'],
            ['timeout', 'orange', 'x']
        ]

if stuff.get('issuance', False):
    matplotlib.rcParams['figure.figsize'] = 18, 12
    call_stuff, rate_stuff = create_latency_meta(stuff['issuance'], conf)
    plot_meta(call_stuff, rate_stuff, 10, stuff.get('issuanceLatency', False))
    plt.savefig("issuance-test.png",bbox_inches='tight')

if stuff.get('ocsp', False):
    call_stuff, rate_stuff = create_meta(stuff['ocsp']. conf)
    plot_meta(call_stuff, rate_stuff, stuff['ocspSent'])
    plt.savefig("ocsp-test.png",bbox_inches='tight')

#plt.show()
