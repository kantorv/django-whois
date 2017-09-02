# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import TopLevelDomain,WhoisServer,Domain,WhoisServiceResponse


# Register your models here.
class TopLevelDomainAdmin(admin.ModelAdmin):
    list_display = ["name","country_code",'get_whois',"created","changed","registar","state","parent",'get_children']
    exclude = ["raw"]
    search_fields = ['name']

    def get_whois(self, obj):
        return "\n".join([w.host for w in obj.whois.all() ])
    get_whois.short_description = "Whois servers"

    def get_children(self, obj):
        if obj.parent:
            return ""

        return ", ".join([s.name for s in obj.subdomains.all() ])
    get_children.short_description = "Subdomains"

class WhoisServernAdmin(admin.ModelAdmin):
    search_fields = ['host','tld__name']
    list_display = ["host",'get_tld',"queryFormat","availablePattern","errorPattern"]
    def get_tld(self, obj):
        return ", ".join([s.name for s in obj.tld.all() ])
    get_tld.short_description = "TLDs"



import datetime
class DomainAdmin(admin.ModelAdmin):
    list_display = ["name", "registered","expired","days_remain",'whois']

    def days_remain(self,obj):
        try:
            ts1 = obj.expired.strftime("%s")
            now = datetime.datetime.now()
            ts2 = now.strftime("%s")
            delta =  (int(ts1) - int(ts2))
            td = datetime.timedelta(seconds=delta)
            return str(td)
        except Exception as e:
            output = str(e)
        return output




admin.site.register(TopLevelDomain, TopLevelDomainAdmin)
admin.site.register(WhoisServer, WhoisServernAdmin)
admin.site.register(Domain, DomainAdmin)