import bcrypt
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User

def index(request):
	if 'logged_in' in request.session:
		if request.session['logged_in'] > datetime.now() - User.objects.login_timeout:
			redirect('/success')
		else:
			redirect('/logout')
	render(request, 'index.html')

def success(request):
	if 'logged_in' not in request.session:
		redirect('/')
	elif request.session['logged_in'] < datetime.now() - User.objects.login_timeout:
		redirect('/logout')
	render(request, 'success.html')

def register(request):
	errors = User.objects.registration_validator(request.POST)
	if errors:
		for key,value in errors:
			messages.error(request, value)
		redirect('/')
	# if User.objects.filter(email_addr__iexact=request.POST['email_addr']):
	# 	errors['email_addr_prev'] = "Email address was previously registered"
	# 	redirect('/')
	User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'],email_addr=request.POST['email_addr'], pw_hash=bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode())
	request.session['logged_in'] = datetime.now()
	redirect('/success')

def login(request):
	errors = User.objects.basic_validator(request.POST)
	if errors:
		for key, value in errors:
			messages.error(request, value)
		redirect('/')
	try:
		user = User.objects.get(email_addr__iexact=request.POST['email_addr'])
	except User.DoesNotExist:
		messages.error(request, "Email address was not found")
		redirect('/')
	if bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode() != user.pw_hash:
		messages.error(request, "Password is incorrect")
		redirect('/')
	request.session['logged_in'] = datetime.now()
	redirect('/success')

def logout(request):
	request.session.flush()
	redirect('/')
