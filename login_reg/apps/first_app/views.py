
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
import bcrypt
from .models import *

  # the index function is called when root is visited
def index(request):
    return render(request, 'first_app/login_reg.html')

def register(request):
    f = request.POST
    valid = True
    if len(f['first_name']) < 4:
        messages.error(request, 'First name must have at least 4 characters.')
        valid = False
    if len(f['last_name']) < 4:
        messages.error(request, 'Last name must have at least 4 characters.')
        valid = False
    if len(f['email']) < 8:
        messages.error(request, 'Email must have at least 8 characters', extra_tags='email')
        valid = False
    if len(f['password']) < 8:
        messages.error(request, 'Password name must have at least 8 characters.')
        valid = False

    if not f['password'] == f['password_confirmation']:
        messages.error(request, 'Password and passowrd confirmation do not match')
        valid = False

    if not valid:
        return redirect('/')
    else:
        if User.objects.filter(email=f['email']).exists():
            messages.error(request, 'You have already registered, please login.')
            return redirect('/')

        hashed_pw = bcrypt.hashpw(f['password'].encode(), bcrypt.gensalt())

        # print("Password is {}".format(hashed_pw))
        User.objects.create(first_name=f['first_name'], last_name=f['last_name'], email=f['email'], 
        password= hashed_pw)

        messages.success(request, 'You are now registered. Please login.')
        return redirect('/')
def login(request):
    f = request.POST
    print(f)
    try:
        user = User.objects.get(email = f['email'])
        password_valid = bcrypt.checkpw(f['password'].encode(), user.password.encode())
        if password_valid:
            request.session['logged_in'] = True
            request.session['user_id'] = user.id
            # send to next page/url
            messages.success(request, 'You are now logged in.')
        else:
            messages.error(request, "Password/email did not match.")
    except User.DoesNotExist:
        messages.error(request, 'Could not find user with this login info.')
    except Exception as err:
        print(err)
        messages.error(request, 'Something else went wrong.')
    return redirect('/')

def logout(request):
    request.session.clear()
    return redirect('/')

def test(request):
    if not 'logged_in' in request.session:
        messages.error(request, 'You need to login to view this page')
    return redirect('/')

    return HttpResponse('You are logged in')


