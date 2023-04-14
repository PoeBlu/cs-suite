import glob
import json
import os
import webbrowser
import subprocess
import awsaudit

account_name = awsaudit.account_name
timestmp = awsaudit.timestmp
script_json = awsaudit.script_json

def trusted_advisor_to_json():
    data = []
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/trusted.json', 'r') as f:
        for line in f:
            k = json.loads(line)
            data.append(k['check'])
    data = set(data)

    for i in data:
        with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/{i}.txt', 'w+') as f:
            with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/trusted.json', 'r') as j:
                for line in j:
                    k = json.loads(line)
                    if k['check'] == i:
                        f.write(line)
    final_json = {}
    report = []
    for f in glob.glob(f"reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/*.txt"):
        dict = {}
        data = []
        with open(f, 'r') as g:
            for line in g:
                j = json.loads(line)
                dict['check'] = j['check']
                new_dict = {
                    'check_no': j['check_no'],
                    'score': j['score'],
                    'level': j['level'],
                    'type': j['type'],
                    'region': j['region'],
                    'value': j['value'],
                }
                data.append(new_dict)
        dict['data'] = data
        report.append(dict)
        final_json['report'] = report
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/final_json', 'w') as f:
        f.write(json.dumps(final_json))
    for f in glob.glob(f"reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/*.txt"):
        os.remove(f)
    json_to_html_trusted()

def json_to_html_trusted():
    with open(f'./reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/trusted_advisor.html', 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
             for line in g:
                  f.write(line)
        with open(f'./reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/final_json', 'r') as json_data:
            final = json.load(json_data)
            for i in final['report']:
                 f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                 f.write('<div class="thumbnail">\n')
                 f.write('<div class="caption">\n')
                 flag = 0
                 for g in i['data']:
                    if g['type'] in ['warning', 'error']:
                        flag = 1
                 if flag == 0:
                    f.write('<div class="grid" style="background-color: green;">')
                 else:
                    f.write('<div class="grid" style="background-color: red;">')
                 f.write('<h5>%s</h5>\n' %(i['check']))
                 f.write('</div>')
                 for k in i['data']:
                      if k['type'] in ['warning', 'error']:
                          f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                      else:
                          f.write('<p>%s</p>\n' %(k['value']))
                 f.write('</div>\n')
                 f.write('</div>\n')
                 f.write('</div>\n')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)


def json_to_final_json():
    report = []
    for f in glob.glob(f"reports/AWS/aws_audit/{account_name}/{timestmp}/delta/*.json"):
        dict = {}
        data = []
        with open(f, 'r') as g:
            for line in g:
                j = json.loads(line)
                dict['check'] = j['check']
                new_dict = {
                    'check_no': j['check_no'],
                    'score': j['score'],
                    'level': j['level'],
                    'type': j['type'],
                    'region': j['region'],
                    'value': j['value'],
                }
                data.append(new_dict)
        dict['data'] = data
        report.append(dict)
        script_json['report'] = report
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/final_json', 'w') as f:
        f.write(json.dumps(script_json))
    for i in script_json['report']:
        if i['check'] in ['CDN_AUDIT', 'CERT_AUDIT', 'DNS_AUDIT', 'ELB_AUDIT']:
            with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/webnet.json', 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        elif i['check'] in ['ELASTIC_CACHE_AUDIT', 'ELASTIC_SEARCH_AUDIT', 'RDS_AUDIT', 'REDSHIFT_AUDIT']:
            with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/datastores.json', 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        elif i['check'] in ['CLOUD_FORMATION_AUDIT', 'SES_AUDIT', 'SNS_AUDIT']:
            with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/notification.json', 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')
        else:
            with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/configs.json', 'a+') as f:
                f.write(json.dumps(i))
                f.write('\n')

def json_to_html_prowler():
    with open(f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/prowler_report.html', 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
             for line in g:
                  f.write(line)
        with open('./tools/prowler/final_json', 'r') as json_data:
             final = json.load(json_data)
             for i in final['report']:
                  f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                  f.write('<div class="thumbnail">\n')
        f.write('<div class="caption">\n')
                  flag = 0
                  for g in i['data']:
                     if g['type'] == 'WARNING':
                         flag = 1
                  if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">')
                  else:
                     f.write('<div class="grid" style="background-color: red;">')
                  f.write('<h5>%s</h5>\n' %(i['check']))
                  f.write('</div>')
                  for k in i['data']:
                       if k['type'] == 'WARNING':
                           f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                       else:
                           f.write('<p>%s</p>\n' %(k['value']))
                  f.write('</div>\n')
                  f.write('</div>\n')
                  f.write('</div>\n')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)

def json_to_html(file, new_file):
    with open(new_file, 'w') as f:
        with open('./tools/prowler/template1.txt', 'r') as g:
            for line in g:
                f.write(line)
        with open(file, 'r') as json_data:
             for line in json_data:
                 line = str(line)
                 final = json.loads(line)
                 f.write('<div class="col-xs-6 col-sm-3 col-md-3 item">\n')
                 f.write('<div class="thumbnail">\n')
                 f.write('<div class="caption">\n')
                 flag = 0
                 for g in final['data']:
                     if g['type'] == 'WARNING':
                         flag = 1
                 if flag == 0:
                     f.write('<div class="grid" style="background-color: green;">')
                 else:
                     f.write('<div class="grid" style="background-color: red;">')
                 f.write('<h5>%s</h5>\n' %(final['check']))
                 f.write('</div>')
                 for k in final['data']:
                     if k['type'] == 'WARNING':
                          f.write('<p><span style="color:red">Warning: </span>%s</p>\n' %(k['value']))
                     else:
                          f.write('<p>%s<p>\n' %(k['value']))
                 f.write('</div>')
                 f.write('</div>')
                 f.write('</div>')
        with open('./tools/prowler/template2.txt', 'r') as k:
             for line in k:
                 f.write(line)


def merge_json():
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/final_json', 'r') as f:
        for line in f:
            j1 = json.loads(line)
    with open('./tools/prowler/final_json', 'r') as k:
        for line in k:
            j2 = json.loads(line)
    for js in j2['report']:
        j1['report'].append(js)
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/final_json', 'w') as f:
        f.write(json.dumps(j1))
    os.remove('./tools/prowler/final_json')

def persistent_json(json_file):

    checks = []
    with open(json_file, 'r') as f:
        for line in f:
            j = json.loads(line)
            checks.append(j['check'])
    checks = set(checks)
    dict = {}
    with open(f'reports/AWS/aws_audit/{account_name}/{timestmp}/delta/final_diff.json', 'w') as g:
        for check in checks:
            dict = {}
            data = []
            with open(json_file , 'r') as f:
                for line in f:
                    j = json.loads(line)
                    if j['check'] == check:
                        dict['check'] = j['check']
                        j.pop('check')
                        data.append(j)
                dict['data'] = data
                g.write("%s\n" % (json.dumps(dict)))


def persis(j1,j2):
    f = open(
        f"./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/diff.json",
        "a+",
    )
    for data1 in j1['data']:
        for data2 in j2['data']:
            if data1==data2:
                pers = json.dumps(data1)
                pers = json.loads(pers)
                if pers['type'] == 'WARNING':
                    pers['check'] = j1['check']
                    f.write("%s\n" % json.dumps(pers))
                    

def persistent(latest, last):
    with open(latest) as data_file:
        data1 = json.load(data_file)
    with open(last) as data_file:
        data2 =  json.load(data_file)

    for d1 in data1['report']:
        for d2 in data2['report']:
            if d2['check'] == d1['check']:
                persis(d1,d2)
    persistent_json(
        f"./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/diff.json"
    )



def persistent_files():
    dirs = os.listdir("./reports/AWS/aws_audit/%s/" % (account_name))
    if len(dirs) == 1:
        print "This is the first audit run for the account, diff will be shown in the next run"
        with open('./reports/AWS/aws_audit/%s/%s/delta/diff.html' % (account_name, timestmp), 'w') as f:
            f.write("This is the first audit for the account, diff will be shown in the next run")
    else:
        last_dir = subprocess.check_output(["ls -td -- */ | head -n 2 | cut -d'/' -f1 | sed -n 2p"], cwd='./reports/AWS/aws_audit/%s' %(account_name), shell=True).strip()
        latest = "./reports/AWS/aws_audit/%s/%s/final_report/final_json" %(account_name, timestmp)
        last = "./reports/AWS/aws_audit/%s/%s/final_report/final_json" %(account_name, last_dir)
        persistent(latest, last)
        json_to_html('./reports/AWS/aws_audit/%s/%s/delta/final_diff.json' % (account_name, timestmp),
                     './reports/AWS/aws_audit/%s/%s/delta/diff.html' % (account_name, timestmp))


def merge():
    if (
        os.stat(
            f'reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/trusted.json'
        ).st_size
        != 0
    ):
        trusted_advisor_to_json()
    json_to_final_json()
    json_to_html_prowler()
    json_to_html(
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/webnet.json',
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/webnet.html',
    )
    json_to_html(
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/datastores.json',
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/datastores.html',
    )
    json_to_html(
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/notification.json',
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/notification.html',
    )
    json_to_html(
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/configs.json',
        f'./reports/AWS/aws_audit/{account_name}/{timestmp}/delta/configs.html',
    )
    merge_json()
    persistent_files()
    subprocess.check_output(
        [
            f'cp -R ./tools/template/* ./reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/'
        ],
        shell=True,
    )
    subprocess.check_output(
        [
            f'rm ./reports/AWS/aws_audit/{account_name}/{timestmp}/final_report/report_azure.html'
        ],
        shell=True,
    )
    webbrowser.open('file://' + os.path.realpath("./reports/AWS/aws_audit/%s/%s/final_report/report.html")
                    % (account_name, timestmp))
    fin = os.path.realpath("./reports/AWS/aws_audit/%s/%s/final_report/report.html") % (account_name, timestmp)
    print(f"THE FINAL REPORT IS LOCATED AT -------->  {fin}")
