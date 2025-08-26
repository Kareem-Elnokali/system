from django.shortcuts import render, redirect
from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib import messages
from django.urls import reverse
def home(request):
    return render(request, 'index.html')
def about(request):
    return render(request, 'about.html')
def contact(request):
    if request.method == 'POST':
        name = request.POST.get('userName', '').strip()
        email = request.POST.get('userEmail', '').strip()
        subject = request.POST.get('userSubject', '').strip() or 'New Contact Form Submission'
        message = request.POST.get('userMessage', '').strip()
        next_url = request.POST.get('next') or reverse('contact')
        if not (name and email and message):
            messages.error(request, 'Please fill in all required fields.')
            return redirect(next_url)
        context = {
            'name': name,
            'email': email,
            'subject': subject,
            'message_body': message,
        }
        html_message = render_to_string('email/contact_form_email.html', context, request=request)
        plain_message = (
            f"You have received a new message from the website contact form.\n\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Subject: {subject}\n\n"
            f"Message:\n{message}\n"
        )
        try:
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=['karim.elnokali222@gmail.com'],
                fail_silently=False,
                html_message=html_message
            )
            messages.success(request, "Thank you! Your message has been sent. We'll get back to you shortly.")
            return redirect(next_url)
        except BadHeaderError:
            messages.error(request, 'Invalid header found.')
            return redirect(next_url)
        except Exception as e:
            err_msg = 'An error occurred while sending your message. Please try again later.'
            if settings.DEBUG:
                err_msg += f" Details: {e}"
                try:
                    print(f"[contact] Email send failed: {e}")
                except Exception:
                    pass
            messages.error(request, err_msg)
            return redirect(next_url)
    return render(request, 'contact-us.html')
