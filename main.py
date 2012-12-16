#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import logging
import time
from string import letters
import webapp2
import jinja2
import random
import hashlib
import hmac
import json

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir=os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                       autoescape=True)

###### Hashing Passwords ######
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)
# Function valid_pw() that returns True if a user's password matches its hash.
def valid_pw(name, pw, h):
    salt=h.split(",")[1]
    return h==make_pw_hash(name,pw,salt)
###################

###### Hashing Cookies ######
SECRET = 'secretcode'
def hash_str(s):
    ###Your code here
    return hmac.new(SECRET,s).hexdigest()
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
###################

###### USER PASS EMAIL VALID ######
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
###################

#### Render_str Global (Mainly for BlogPost Class) ####
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
###################

#### Handler class for web request writes,renders etc. ####
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template,**params):
        t=jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self,name,value):
        cookie_val=make_secure_val(value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name,cookie_val))
    def read_secure_cookie(self,name):
        cookie_val=self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        uid=self.read_secure_cookie('user_id')
        self.user= uid and User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'
            
    def login(self,user):
        self.set_secure_cookie('user_id',str(user.key().id()))
    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')
###################

###### Main stuff ######
class MainPage(Handler):
  def get(self):
      self.write('Hello, World! ->  ')
      self.response.headers['Content-Type']='text/plain'
      visits=0
      visit_cookie_str = self.request.cookies.get('visits')
      if visit_cookie_str:
        cookie_val=check_secure_val(visit_cookie_str)
        if cookie_val:
            visits=int(cookie_val)

      visits +=1

      new_cookie_val= make_secure_val(str(visits))
      self.response.headers.add_header('Set-Cookie','visits=%s' % new_cookie_val)
      if visits>10 and visits<16:
          self.write("You are the best ever!")
      elif visits>15 and visits<21:
          self.write("Keep it up!!!")
      elif visits>20:
          self.write("Your a power user!!   ")
          self.write("You've been here %s times" % visits)
      else:
          self.write("You've been here %s times" % visits)
###################

###### Cache stuff ######          
def top_posts(update=False):
    mem_key='top'
    posts=memcache.get(mem_key)
    if posts is None or update:
        logging.error("Top Posts -- DB QUERY")
        posts= db.GqlQuery("SELECT * from BlogPost ORDER BY created DESC limit 10")
        posts=[list(posts),time.time()]
        memcache.set(mem_key,posts)
    return posts[0],posts[1]
def perma_post(post_id,update=False):
    mem_key='perma_%s'%post_id
    post=memcache.get(mem_key)
    if post is None or update:
        logging.error("PERMALINK -- DB QUERY")
        key = db.Key.from_path('BlogPost', int(post_id),parent=blog_key())
        post = [db.get(key),time.time()]
        memcache.set(mem_key,post)
    return post[0],post[1]
def time_cached_ago(time_cached):
    a=str(time.time()-time_cached).split(".")
    return a[0]

class FlushCache(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')
###################

###### Blog stuff ######
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)
def user_key(group='default'):
    return db.Key.from_path('users', group)

class BlogPost(db.Model) :
    subject=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    last_modified=db.DateTimeProperty(auto_now=True)

    def render(self):
        self._render_text=self.content.replace('\n','<br>')
        return render_str("post.html",p=self)
    
    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d
    
class User (db.Model):
    name=db.StringProperty(required=True)
    pw_hash=db.StringProperty(required=True)
    email=db.StringProperty()

    @classmethod
    def by_id(cls,uid):
        return cls.get_by_id(uid,parent=user_key())
    @classmethod
    def by_name(cls,name):
        u=cls.all().filter('name =',name).get()
        return u
    @classmethod
    def register(cls,name,pw,email=None):
        pw_hash=make_pw_hash(name,pw)
        return User(parent=user_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)
    @classmethod
    def login(cls,name,pw):
        u=cls.by_name(name)
        if u and valid_pw(name,pw,u.pw_hash):
            return u

class PostPage(Handler):
    def get(self, post_id):
        post,time_cached=perma_post(post_id)
        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", p = post, time_cached=time_cached_ago(time_cached))
        else:
            self.render_json(post.as_dict())

class BlogFront(Handler):
    def render_front(self):
        posts,time_cached=top_posts()
        if self.format == 'html':
            self.render("index.html",user=self.user,posts=posts,time_cached=time_cached_ago(time_cached))
        else:
            return self.render_json([p.as_dict() for p in posts])
    def get(self):
        self.render_front()

class NewPost(Handler):
    def get(self):
        #if self.user:
        self.render("newpage.html")
        #else:
         #   self.error(403)
    def post(self):
        subject=self.request.get("subject")
        content=self.request.get("content")
        if subject and content:
            p=BlogPost(parent=blog_key(), subject=subject,content=content)
            p.put()
            self.redirect('/blog/%s'%str(p.key().id()))
        else:
            error="Please fill both Subject and Content!"
            self.render("newpage.html",content=content,subject=subject,error = error)

class Welcome(Handler):
    def get(self):
        if self.user: #self.user from Handler on initialize
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/blog/signup')
class Signup(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()
    def done(self,*a,**kw):
        raise NotImplementedError
class Register(Signup):
    def done(self):
        #make sure user doesn't exist
        u=User.by_name(self.username)
        if u:
            msg='That user already exists.'
            self.render('signup-form.html',error_username=msg)
        else:
            u=User.register(self.username,self.password,self.email)
            u.put()
            self.login(u)
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        if not self.user:
            self.render("login-form.html")
        else:
            self.write("Already logged in %s!" % (self.user.name))
    def post(self):
        self.username=self.request.get('username')
        self.password=self.request.get('password')

        u=User.login(self.username,self.password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg="Wrong Username/Password"
            self.render("login-form.html",username=self.username,error=msg)
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/login')

###################

####WIKI######
class WikiPost(db.Model) :
    page=db.StringProperty(required=True)
    content=db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)
    last_modified=db.DateTimeProperty(auto_now=True)
    user=db.StringProperty()

    def render(self):
        self._render_text=self.content.replace('\n','<br>')
        return render_str("wikipost.html",p=self)
    
    @classmethod
    def by_name(cls,name):
        u=cls.all().filter('page =',name).get()
        return u
    @classmethod
    def by_id(cls,uid):
        return cls.get_by_id(uid)
    
    @classmethod
    def createwp(cls,page,content):
        return WikiPost(page=page,
                    content=content)
    
class EditPage(Handler):
    page1='/'
    def get(self,page):
        v=self.request.get('v')
        if self.user:
            global page1
            page1=str(page)
            if v:
                wikipost=WikiPost.by_id(int(v))
                if wikipost:
                   self.render("newwiki.html",content=wikipost.content,user=self.user,page=page)
                else:    
                    self.render("newwiki.html",content='',user=self.user,page=page)
            else:
                wikipage=WikiPost.by_name(page)
                if wikipage:
                    wikipost=WikiPost.gql("WHERE page = :1 ORDER BY created DESC", str(page))
                    content=wikipost[0].content
                    self.render("newwiki.html",content=content,user=self.user,page=page)
                else:    
                    self.render("newwiki.html",content='',user=self.user,page=page)
        else:
            self.error(403)
    def post(self,page1):
        v=self.request.get('v')
        if self.user:
            self.wikipage=page1
            self.content=self.request.get('content')
            if v:
                wikipost=WikiPost.by_id(int(v))
                wikipost.content=self.content
                wikipost.put()
                self.redirect('/wiki?v='+str(wikipost.key().id()))
            else:
                wp=WikiPost.createwp(self.wikipage,self.content)
                wp.put()
                self.redirect('/wiki'+page1)
        else:
            self.redirect('/wiki/login')
class HistoryPage(Handler):
    def get(self,page):
        v=self.request.get('v')
        wikipost=WikiPost.gql("WHERE page = :1 ORDER BY created DESC", page)
        self.render("wikihistory.html",wikipost=wikipost,user=self.user,page=page)
class WikiPage(Handler):
    def get(self,page):
        v=self.request.get('v')
        if not page:
            page='/'
        if v:
            wikipost=WikiPost.by_id(int(v))
            self.render("wikipage.html",wikipost=wikipost.content,user=self.user,page=page)
        else:
            wikipage=WikiPost.by_name(page)
            if wikipage:
                wikipost=WikiPost.gql("WHERE page = :1 ORDER BY created DESC", page)
                content=wikipost[0].content
                self.render("wikipage.html",wikipost=content,user=self.user,page=page)
            else:
                if self.user:
                    self.redirect('/wiki/_edit'+page)
                else:
                    self.redirect('/wiki')

PAGE_RE = r'(/?(?:[a-zA-Z0-9_-]+/?)*)'        
###################
app = webapp2.WSGIApplication([('/blog/?(?:\.json)?', BlogFront),
                               ('/blog/welcome?', Welcome),
                               ('/blog/flush?', FlushCache),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/wiki/signup', Register),
                               ('/wiki/login', Login),
                               ('/wiki/logout', Logout),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)(?:\.json)?', PostPage),
                               ('/wiki/_edit' + PAGE_RE, EditPage),
                               ('/wiki/_history' + PAGE_RE, HistoryPage),
                               ('/wiki' + PAGE_RE, WikiPage),
                               ('/?', MainPage)],
                              debug=True)
