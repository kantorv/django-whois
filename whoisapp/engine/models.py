# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
# Create your models here.


class WhoisServer(models.Model):
    host = models.CharField(max_length=1024,blank=True, default=None, unique=True)
    source = models.CharField(max_length=1024,blank=True, default=None,null=True)
    queryFormat = models.CharField(max_length=1024,blank=True, default=None,null=True)
    availablePattern = models.CharField(max_length=1024,blank=True, default=None,null=True)
    errorPattern = models.CharField(max_length=1024,blank=True, default=None,null=True)

    def __unicode__(self):
        return self.host

    def get_tlds(self, print_res=False):
        res = ",".join([s.name for s in self.tld.all() ])
        if print_res: print (res)
        return res




class TopLevelDomain(models.Model):
    name = models.CharField(max_length=1024,blank=True, default=None, unique=True)
    country_code = models.CharField(max_length=10,blank=True,null=True, default=None)
    created = models.DateTimeField(blank=True,null=True, default=None)
    changed = models.DateTimeField(blank=True, null=True,default=None)
    registar = models.CharField(max_length=1024,blank=True,null=True, default=None)
    source = models.CharField(max_length=20,blank=True,null=True, default=None)
    state = models.CharField(max_length=20,blank=True,null=True, default=None)  #[u'ACTIVE', u'NEW', u'INACTIVE']
    whois = models.ManyToManyField(WhoisServer, blank=True, default=None, related_name="tld")
    parent =   models.ForeignKey('self', on_delete=models.CASCADE, related_name='subdomains' , null=True , blank=True)
    raw =  models.TextField(blank=True, default=None, null=True)

    def __unicode__(self):
        return  self.name

    def get_whois(self):
        if self.whois.count():
            return self.whois.all()
        return self.parent.whois.all()




class Domain(models.Model):
    name = models.CharField(max_length=1024,unique=True)
    registered = models.DateTimeField(blank=True,null=True,default=None)
    expired = models.DateTimeField(blank=True,null=True,default=None)
    whois = models.ForeignKey(WhoisServer,null=True, default=None, related_name="domains")
    def __unicode__(self):
        return  self.name


class WhoisServiceResponse(models.Model):
    domain = models.ForeignKey(Domain, related_name="queries")
    created = models.DateTimeField(auto_now_add=True)
    whois = models.ForeignKey(WhoisServer,related_name="responses")
    raw = models.TextField()
    parsed =  models.TextField()


    def __unicode__(self):
        return "{} :: {}".format( self.domain,self.whois )