# def Register(request):
#     if request.method == 'POST':
#         username = request.POST['user1']
#         email = request.POST['email1']
#         password = request.POST['pass1']
#         confirmpassword = request.POST['cpass1']

#         if(is_valid_username(username) == True and is_valid_email(email) == True):
#             if(is_valid_password(password, confirmpassword) == True):
#                 user1 = AddUser(Username=username, Email=email, Password=password)
#                 token = Token.objects.create(user=user1)
#                 user1.save()
#                 print(token.key)
#             else:
#                 message = is_valid_password(password, confirmpassword)
#                 messages.info(request, message)
#         else:
#             message = is_valid_username(username)
#             if message is not True:
#                 messages.info(request, message)
#             else:
#                 messages.info(request, "Email is incorrect format!")
        

#     return render(request, "RegisterPage.html")