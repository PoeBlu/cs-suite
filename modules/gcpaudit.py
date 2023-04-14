from __future__ import print_function
import subprocess
import os
import time
import webbrowser

timestmp = time.strftime("%Y%m%d-%H%M%S")

def gcp_audit(project_name):
    """ This function just calls the G-Scout to Audit GCP """
    subprocess.call(['mkdir', '-p', f'reports/GCP/{project_name}/{timestmp}'])
    print ("Starting GCP Audit")
    subprocess.call(['python', 'gscout.py', 'project', project_name], cwd='tools/G-Scout')
    if os.path.exists(f"tools/G-Scout/Report Output/{project_name}"):
        subprocess.check_output(['mv tools/G-Scout/Report\ Output/%s/* reports/GCP/%s/%s/' % (project_name, project_name, timestmp)], shell=True)
        subprocess.check_output(['rm -rf tools/G-Scout/Report\ Output/%s' % (project_name)], shell=True)
        webbrowser.open('file://' + os.path.realpath("./reports/GCP/%s/%s/All Ports Open to All.html") % (project_name, timestmp))
        fin = os.path.realpath("./reports/GCP/%s/%s/All\ Ports\ Open\ to\ All.html") % (project_name, timestmp)
        print(f"THE FINAL REPORT IS LOCATED AT -------->  {fin}")

