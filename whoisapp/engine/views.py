# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render
from django.views.generic import View
from .utils import get_whois_data
from json2html import *



class Home(View):
    template_name = 'home.html'
    def get(self, request):
        query = request.GET.get('q')
        error = ""
        resp = ""
        if query:
            query = query.strip()
            try:
                resp = get_whois_data(query)
            except Exception as e:
                error = str(e)

            if "parsed"  in resp:
                del resp['parsed']['raw']
                table = json2html.convert(json = resp.get('parsed'), table_attributes="class=\"table table-condensed table-bordered table-hover\"")
                resp['table'] = table


        return render(request, self.template_name, { "query" : query, "error" : error, "resp" : resp})