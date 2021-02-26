import bcrypt
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User

def index(request):
	if 'logged_in' in request.session:
		logged_in_time = datetime.strptime(request.session['logged_in']['time'], '%Y-%m-%d')
		if logged_in_time > datetime.now() - User.objects.login_timeout:
			if logged_in_time < datetime.now() - timedelta(seconds=2):
				messages.success(request, "You are still logged in", "alert-success")
			return redirect('/success')
		else:
			return redirect('/logout')
	return render(request, 'index.html')

def success(request):
	if 'logged_in' not in request.session:
		return redirect('/')
	logged_in_time = datetime.strptime(request.session['logged_in']['time'], '%Y-%m-%d')
	if logged_in_time < datetime.now() - User.objects.login_timeout:
		return redirect('/logout')
	context = {
		'user': User.objects.get(id=request.session['logged_in']['user'])
	}
	return render(request, 'success.html', context)

def register(request):
	warnings = User.objects.registration_validator(request.POST)
	if warnings:
		for key, value in warnings.items():
			messages.warning(request, value, "alert-warning")
		return redirect('/')
	pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
	user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], birth_date=datetime.strptime(
		request.POST['birth_date'], '%Y-%m-%d').date(), email_addr=request.POST['email_addr'], pw_hash=pw_hash)
	request.session['logged_in'] = {}
	request.session['logged_in']['user'] = user.id
	request.session['logged_in']['time'] = datetime.now()
	messages.success(request, "Registration Successful!!", "alert-success")
	return redirect('/success')

def login(request):
	errors = User.objects.basic_validator(request.POST)
	if errors:
		for key, value in errors.items():
			messages.error(request, value, "alert-danger")
		return redirect('/')
	try:
		user = User.objects.get(email_addr__iexact=request.POST['email_addr'])
	except User.DoesNotExist:
		messages.error(request, "Email address was not found", "alert-danger")
		return redirect('/')
	pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
	if not bcrypt.checkpw(request.POST['password'].encode(), user.pw_hash.encode()):
		messages.error(request, "Password is incorrect", "alert-danger")
		return redirect('/')
	request.session['logged_in'] = {}
	request.session['logged_in']['user'] = user.id
	request.session['logged_in']['time'] = datetime.now().strftime('%Y-%m-%d')
	messages.success(request, "Login Successful!!", "alert-success")
	return redirect('/success')

def logout(request):
	request.session.flush()
	return redirect('/')
