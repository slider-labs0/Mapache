FROM httpd:2.4
RUN sed -i 's/Options Indexes FollowSymLinks/Options +Indexes/' /usr/local/apache2/conf/httpd.conf || true
RUN printf 'Options +Indexes\n' >> /usr/local/apache2/conf/httpd.conf
COPY site/ /usr/local/apache2/htdocs/
