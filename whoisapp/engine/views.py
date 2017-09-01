# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.views.generic import View
from .utils import perform_whois_query

# Create your views here.
class Home(View):
    template_name = 'home.html'
    def get(self, request):
        query = request.GET.get('q')
        error = ""
        resp = ""
        if query:
            query = query.strip()
            try:
                resp = perform_whois_query(query)
            except Exception as e:
                error = str(e)
        return render(request, self.template_name, { "query" : query, "error" : error, "resp" : resp})