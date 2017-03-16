import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'table_flip_no_workie_cdkscds43&67%#@909jnstsy@?0(0'

### standard class framework

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

###

class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        # same as saying
        # if cookie_val and check_secure_val(cookie_val):
        #     return cookie_val
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)



### user stuff

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)

# user object to be stored in db

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        # datastore procedural look up
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u



### blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)



class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    name = db.ReferenceProperty(User)
    likes = db.IntegerProperty()



    @property
    def like_count(likes):
        return likes.length

    def render(self, user):
        comments = Comment.all().filter('post_id =', self).order('-created')
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, user=user, comments=comments)



class Likes(db.Model):
    name = db.StringProperty(required=True)
    post_id = db.IntegerProperty()
    comment_id = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)



class Comment(db.Model):
    content = db.TextProperty(required = True)
    post_id = db.ReferenceProperty(Post)
    name = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True )
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(required = False)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", p = self)

class HomePage(Handler):

    def get(self):
        #posts = Post.all().order('-created')
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(Handler):
    """page for particular post"""

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/signup')
        subject = self.request.get('subject')
        content = self.request.get('content')
        name = self.request.get('name')
        likes = 0
        q = User.all().filter('name =', name)

        for name in q.run():
            pass

        if subject and content:
            p = Post(parent=blog_key(), subject=subject,
                            content=content, likes=likes, name=self.user)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = 'You did not enter subject or content!'
            self.render("newpost.html", subject=subject, content=content,
                        error=error, comments=comments)


# sign up stuff

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

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
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


class EditPost(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("editpost.html", post=post)

    def post(self, post_id):

        if not self.user:
            return self.redirect('/signup')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            return self.redirect('/')

        if post.name.key().id() != self.user.key().id():
            return self.redirect('/%s' % str(post.key().id()))

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/%s' % str(post.key().id()))
        else:
            error = 'You did not enter subject or content!'
            self.render("newpost.html", subject=subject, content=content,
                        error=error, likes=likes, author=author)


class DeletePost(Handler):

    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if not self.user:
                self.redirect("/login")
            else:
                self.render('deletepost.html', post_id=id)

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)

            post.delete()
            self.redirect('/')
        else:
            return self.redirect('/login')



class NewComment(Handler):

    def get(self, post_id):
        if self.user:
            self.render("comment.html", postId= post_id)
        else:
            self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        content = self.request.get('content')
        name = self.request.get('name')
        created = self.request.get('created')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())

        posts = db.get(key)

        if posts == None:
            return self.redirect('/')

        if content:
            c = Comment(content=content, name=name, post_id=posts)
            c.put()
            return self.redirect('/')
        else:
            error = "subject and content, please!"
            self.render("comment.html", content=content, error=error)


class EditComment(Handler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Comment', int(post_id))
            comments = db.get(key)
            if comments == None or comments.name != self.user.name:
                return self.redirect('/')
            self.render("editcomment.html", comments = comments)
        else:
            return self.redirect('/login')


    def post(self, comment_id):
        if not self.user:
            return self.redirect('/login')
        content = self.request.get('content')
        name= self.request.get('name')
        key = db.Key.from_path('Comment', int(comment_id))
        comments = db.get(key)
        if comments == None or comments.name != self.user.name:
            return self.redirect('/')
        if content:
            comments.content = content
            comments.name = name
            comments.put()
            self.redirect('/')
        else:
            error = 'Please add some content'
            self.render('editcomment.html', content=content, error=error)




class DeleteComment(Handler):

    def get(self, post_id):
        key = db.Key.from_path('Comment', post_id)
        comments = db.get(key)

        if not self.user:
            self.redirect("/login")
        else:
            self.render('deletecomment.html', post_id=id)

    def post(self, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id))
            comments = db.get(key)

            comments.delete()
            self.redirect('/')




class LikePost(Handler):

    def post(self, post_id):
        if not self.user:
            return self.redirect("/login")

        name = self.user.name
        q = db.Query(Likes)
        q.filter('post_id =', int(post_id)).filter('name =', name)
        created = ''
        for p in q.run():
            return self.redirect('/')

        pid = int(post_id)
        l = Likes(name = name, post_id = pid)
        l.put()
        key = db.Key.from_path("Post", pid, parent=blog_key())
        posts = db.get(key)
        if posts == None:
            return self.redirect('/')

        if posts.likes == None:
            posts.likes = 1
        else:
            posts.likes += 1
        posts.put()
        self.redirect('/')



class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')


class Welcome(Handler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')



app = webapp2.WSGIApplication([('/', HomePage),
                               ('/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/([0-9]+)/editpost', EditPost),
                               ('/([0-9]+)/deletepost', DeletePost),
                               ('/newcomment/([0-9]+)', NewComment),
                               ('/editcomment/([0-9]+)', EditComment),
                               ('/deletecomment/([0-9]+)', DeleteComment),
                               ('/([0-9]+)/like', LikePost),
                               ('/welcome', Welcome),
                               ],
                              debug=True)