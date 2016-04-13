#!/usr/bin/env python
#
# stix2misp.py
#
# Uses python-stix package and PyMISP package to convert existing STIX
# XML files to MISP objects
#
# REQUIREMENTS:
# python-stix: https://github.com/STIXProject/python-stix
# PyMISP: https://github.com/MISP/PyMISP
#
# USAGE:
#   python stix2misp.py -i <file_name>
#

from stix.core import STIXPackage
from pymisp import PyMISP
from pprint import pprint
import argparse
import requests
import time
import base64
import os
import glob
import re

def mispBuildEvent(misp,misp_url, misp_key,misp_title,misp_date,args):
    # Build the new event
    if not args.distrib:
        args.distrib=0
    if not args.threat:
        args.threat=3
    if not args.analysis:
        args.analysis=2    
    
    event = misp.new_event(args.distrib,args.threat,args.analysis,misp_title)
    time.sleep(0.2)
    
    # Add tags the user requested
    if args.tag:
        tags=args.tag.split(",")
        print "tags: "+str(tags)
        for tag in tags:
            tag = tag.strip()
            print "Tagging with: "+tag
            out=misp.add_tag(event, tag)
            print "Response: "+str(out)
            
            # Add tag as internal reference
            misp.add_internal_other(event, tag)
            
            # print "out errors: "+out['errors']
            # exit(0)
            
            if 'errors' in out and out['errors']=='Invalid Tag.':
                print "Tag does not exist. Adding Tag..."
                out=misp.new_tag(tag, exportable=True)
                print "Response: "+str(out)
                print "Attempting to add tag '"+str(tag)+"' again..."
                out=misp.add_tag(event, tag)
                print "Response: "+str(out)
                
    
    
    return event

def mispBuildObject(object_type, properties, event, args):
    
    # Set MISP instance
    misp = PyMISP(misp_url, misp_key, True, 'json')
    
    # Process Args
    if not args.ids:
        args.ids=True
    
    # Grab important info from File Objects
    if "FileObjectType" in str(object_type):
        # print dir(properties)
        print "        file_format: "+str(properties.file_format)
        print "        file_name: "+str(properties.file_name)
        print "        file_path: "+str(properties.file_path)
        print "        md5: "+str(properties.md5)
        print "        sha1: "+str(properties.sha1)
        print "        peak_entropy: "+str(properties.peak_entropy)
        print "        sha_224: "+str(properties.sha224)
        print "        size: "+str(properties.size)
        print "        size_in_bytes: "+str(properties.size_in_bytes)
        # print "        hashes_dir: "+str(dir(properties.hashes))
        
        # Get other file info
        if properties.file_name:
            file_name=str(properties.file_name)
        else:
            file_name=""
        if properties.file_path:
            file_path=str(properties.file_path)
        else:
            file_path=""
        if properties.size:
            size = str(properties.size)
        elif properties.size_in_bytes:
            size = str(properties.size_in_bytes)
        else:
            size = ""
        if properties.file_format:
            file_format = str(properties.file_format)
        else:
            file_format = ""
            
        # Build the comment w/ related info
        comment = ""
        if file_path:
            comment="[PATH] "+file_path
        if size:
            if comment:
                comment=comment+" | [SIZE] "+size
            else:
                comment="[SIZE] "+size
        if file_format:
            if comment:
                comment = comment+" | [FORMAT] "+file_format
            else:
                comment = "[FORMAT] "+file_format
        
        for hash in properties.hashes:
            print "        "+str(hash.type_)+": "+str(hash)

            # Add to MISP
            if str(hash.type_)=="MD5":
                # Add the hash by itself
                #misp.add_hashes(event, md5=str(hash))
                misp.add_hashes(event, filename=str(properties.file_name), md5=str(hash), comment=comment, to_ids=args.ids)
                
            elif str(hash.type_)=="SHA1":
                # Add the hash by itself
                #misp.add_hashes(event, sha1=str(hash))
                misp.add_hashes(event, filename=str(properties.file_name), sha1=str(hash), comment=comment, to_ids=args.ids)
                
            elif str(hash.type_)=="SHA256":
                # Add the hash by itself
                #misp.add_hashes(event, sha256=str(hash))
                misp.add_hashes(event, filename=str(properties.file_name), sha256=str(hash), comment=comment, to_ids=args.ids)
                
            elif str(hash.type_)=="SSDEEP":
                # Add the hash by itself
                #misp.add_hashes(event, ssdeep=str(hash))
                misp.add_hashes(event, filename=str(properties.file_name), ssdeep=str(hash), comment=comment, to_ids=args.ids)
                
        
    # Grab important info from Mutex Objects
    if "MutexObjectType" in str(object_type):
        print "        name: "+str(properties.name)
        
        # Add to MISP
        misp.add_mutex(event, str(properties.name), to_ids=args.ids)
        
    # Grab important info from Registry Keys:
    if "WindowsRegistryKeyObjectType" in str(object_type):
        print "        key: "+str(properties.key)
        if properties.values:
            for value in properties.values:
                print "        value.datatype: "+str(value.datatype)
                print "        value.data: "+str(value.data)
                #print "        value: "+str(dir(value))
                
                # Add to MISP
                misp.add_regkey(event, str(properties.key), rvalue=str(value.data), to_ids=args.ids)
        else:
            misp.add_regkey(event, str(properties.key), to_ids=args.ids)
                
    # Grab Domain Names:
    if "DomainNameObjectType" in str(object_type):
        print "        domain: "+str(properties.value)
        
        # Add to MISP
        misp.add_domain(event, str(properties.value), to_ids=args.ids)
        
    # Grab URI's
    if "URIObjectType" in str(object_type):
        print "        uri: "+str(properties.value)
        
        # Add to MISP
        misp.add_url(event, str(properties.value), to_ids=args.ids)

    # Grab Ports
    if "PortObjectType" in str(object_type):
        print "        port: "+str(properties.port_value)

    # Grab Email Info
    if "EmailMessageObjectType" in str(object_type):
        print "        date: "+str(properties.date)
        print "        from: "+str(properties.from_)
        
        print "        sender: "+str(properties.sender)
        if properties.from_:
            misp.add_email_src(event, str(properties.from_), to_ids=args.ids)
        elif properties.sender:
            misp.add_email_src(event, str(properties.sender), to_ids=args.ids)
        
        print "        to: "+str(properties.to)
        if properties.to:
            misp.add_email_dst(event, str(properties.to), to_ids=args.ids)
        
        print "        subject: "+str(properties.subject)
        if properties.subject:
            misp.add_email_subject(event, str(properties.subject), to_ids=args.ids)
        
        
        print "        reply_to: "+str(properties.reply_to)
        if properties.reply_to:
            misp.add_email_src(event, str(properties.reply_to), comment="Reply-To Address", to_ids=args.ids)
            
        print "        message_id: "+str(properties.message_id)
        
        print "        x_originating_ip: "+str(properties.x_originating_ip)
        if properties.x_originating_ip:
            misp.add_ipsrc(event, str(properties.x_originating_ip), comment="MAIL X-Origin-IP", to_ids=args.ids)
        
        print "        email_server: "+str(properties.email_server)
        # print "        attachments: "+str(properties.attachments)
        # print "        links: "+str(properties.links)
        
def processDescriptions(misp,event,filename,all_desc):
    # Set the file name
    filepath="./"+filename
    
    # Grab the data from the current event
    event_id = event['Event']['id']
    distribution = event['Event']['distribution']
    to_ids = False
    category = 'External analysis'
    info = event['Event']['info']
    analysis = event['Event']['analysis']
    threat_level_id = event['Event']['threat_level_id']
        
    # Build the post data
    to_post = misp.prepare_attribute(event_id, distribution, to_ids,
                                     category, info, analysis, threat_level_id)
    to_post['request']['files'] = [{'filename':filename, 'data': base64.b64encode(all_desc)}]
    out = misp._upload_sample(to_post)
    
def forceTag(pkg, args, misp, event, tag):
    if args.mask:
        if not re.match(args.mask,tag):
            print str(tag)+" does not match the regular expression "+str(args.mask)
            print "Skipping tag"
            return
        else:
            print str(tag)+" matches the regular expression "+str(args.mask)
    print "adding FORCETAG: "+tag
    out=misp.add_tag(event, tag)
    print "Response: "+str(out)
    if 'errors' in out and out['errors']=='Invalid Tag.':
        print "Tag does not exist. Adding Tag..."
        out=misp.new_tag(tag, exportable=True)
        print "Response: "+str(out)
        print "Attempting to add tag '"+str(tag)+"' again..."
        out=misp.add_tag(event, tag)
        print "Response: "+str(out)

        
def processSTIX(pkg, args, misp_url, misp_key):
    # Load the PyMISP functions
    misp = PyMISP(misp_url, misp_key, True, 'json')
    
    # Build the event and add tags if applicable
    misp_title = str(pkg._id)+" | "+str(pkg.stix_header.title)
    misp_date = str(pkg.timestamp)
    
    event = mispBuildEvent(misp,misp_url,misp_key,misp_title,misp_date,args)
    
    # Process force-tags if applicable
    
    if args.forcetag:
        # Add the package ID as a tag
        try:
            tag = str(pkg._id)
        except AttributeError:
            tag = ""
        if tag:
            forceTag(pkg, args, misp, event, tag)
            # Add Internal Reference Attribute
            misp.add_internal_other(event, tag)
            
        # Add the package title as a tag
        try:
            tag = str(pkg.stix_header.title)
        except AttributeError:
            tag = ""
        if tag:
            forceTag(pkg, args, misp, event, tag)
            # Add Internal Reference Attribute
            misp.add_internal_other(event, tag)
            
        # Add the sender's name as a tag
        try:
            tag = str(pkg.stix_header.information_source.identity.name)
        except AttributeError:
            tag = ""
        if tag:
            forceTag(pkg, args, misp, event, tag)
            # Add Internal Reference Attribute
            #
            # Commenting this out because it would end up saying every STIX document
            # coming from the same originator is related.
            #
            # misp.add_internal_other(event, tag)
    
    
    # Output to screen
    print "\r\n##################"
    print "ID: "+str(pkg._id)
    print "Title: "+str(pkg.stix_header.title)
    print "Time: "+str(pkg.timestamp)
    print "##################\r\n"

    all_inc_desc=""
    all_ind_desc=""
    
    # Loop through all incidents
    for inc in pkg.incidents:
        # Get incindent descriptions
        for inc_desc in inc.descriptions:
            if inc_desc:
                inc_desc = str(inc_desc)
                all_inc_desc = all_inc_desc+"=============NEW DESCRIPTION=============\n\n"+inc_desc
        
    # Loop through all indicators
    for ind in pkg.indicators:
        
        for type in ind.indicator_types:
            print "Indicator Type: "+str(type)

        # Collect indicator descriptions
        for ind_desc in ind.descriptions:
            if ind_desc:
                ind_desc = str(ind_desc)
                all_ind_desc = all_ind_desc+"\n\n=============NEW DESCRIPTION=============\n\n"+ind_desc
        
        # For processing STIX w/ composite_indicator_expression(s)
        if ind.composite_indicator_expression:
            for cie in ind.composite_indicator_expression:
                properties=cie.observable.object_.properties
                object_type=properties._XSI_TYPE
                
                print "    Observable type: "+str(object_type)
                # processObject(object_type, properties)
                mispBuildObject(object_type, properties, event, args)
                
        # For processing STIX that without composite_indicator_expression(s)        
        else:
            properties=ind.observable.object_.properties
            object_type=properties._XSI_TYPE
            
            print "    Observable type: "+str(object_type)
            # processObject(object_type, properties)
            mispBuildObject(object_type, properties, event, args)
        
        
    # Process Descriptions and add as files to MISP    
        
    if all_ind_desc:
        # Grab all the descriptions and add them to the event in a text file
        filename=str(event['Event']['id'])+"_Indicator_Descriptions.txt"
        processDescriptions(misp,event,filename,all_ind_desc)
    if all_inc_desc:
        # Grab all the descriptions and add them to the event in a text file
        filename=str(event['Event']['id'])+"_Incident_Descriptions.txt"
        processDescriptions(misp,event,filename,all_inc_desc)

if __name__ == "__main__":

    # MISP Login Info - CHANGE THIS OR IT WON'T WORK!
    misp_url = 'http://<your_misp_url>'
    misp_key = '<your_misp_api_key>'

    # Input Parser
    
    parser = argparse.ArgumentParser(description="EXAMPLE: stix2misp.py -i stix_file.xml -T \"custom tag, tag2\" -F -m \"^[A-Z0-9-]*$\"")
    parser.add_argument("-i", "--input", type=str, required=True, help="STIX file to upload to MISP")
    parser.add_argument("-d", "--distrib", type=int, help="The distribution setting used for the attributes and for the newly created event, if relevant. [0-3]. DEFAULT: 0")
    parser.add_argument("-ids", action='store_false', help="Setting this flag tells MISP NOT to add these to the IDS")
    parser.add_argument("-a", "--analysis", type=int, help="The analysis level of the newly created event, if applicatble. [0-2] DEFAULT: 2")
    parser.add_argument("-t", "--threat", type=int, help="The threat level ID of the newly created event, if applicatble. [1-4] DEFAULT: 3")
    parser.add_argument("-T", "--tag", type=str, help="Add a comma-separated list of tags to add to the event")
    parser.add_argument("-F", "--forcetag", action='store_true', help="Automatically adds the Title and ID of the STIX package as tags")
    parser.add_argument("-m", "--mask", type=str, help="Add a Regex mask for the forcetag option to avoid unnecessarily long tagging (e.g. \"^[A-Z0-9-]*$\"). Must be run in conjunction with -F.")
    # parser.add_argument("-tkt", type=str, help="Add a ticket number as an internal reference")
    args = parser.parse_args()
    
    # Build the intial STIX object
    files=[]
    if os.path.isfile(args.input):
        files = [args.input]
    elif os.path.isdir(args.input):
        files = [f for f in glob.iglob(os.path.join(args.input + '*'))]
    else:
        print "Invalid file"
        exit(0)
    
    
    # Process the STIX file(s)
    for stix_file in files:
        pkg = STIXPackage.from_xml(stix_file)
        processSTIX(pkg, args, misp_url, misp_key)
        
        
