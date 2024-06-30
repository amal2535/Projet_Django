from django.utils import timezone
from django.contrib.auth.decorators import login_required
from datetime import timedelta, datetime
from .models import Progress
from django.http import JsonResponse

@login_required
def navbar_data(request):
    user_progress = Progress.objects.filter(user=request.user)
    response = []

    risk_levels = {'extreme': 1, 'high': 2, 'medium': 3, 'low': 4}

    for progress in user_progress:
        exam_date = progress.exam_date
        current_date = timezone.now().date()

        if exam_date <= current_date:
            continue

        exam_datetime_naive = datetime.combine(exam_date, datetime.min.time())
        exam_datetime = timezone.make_aware(exam_datetime_naive, timezone.get_current_timezone())
        remaining_time = exam_datetime - timezone.now()

        predicted_time = timedelta(days=progress.days_predicted, hours=progress.hours_predicted)

        if remaining_time < predicted_time:
            total_hours_predicted = progress.days_predicted * 24 + progress.hours_predicted
            remaining_hours = remaining_time.total_seconds() / 3600

            if remaining_hours <= total_hours_predicted * 0.25:
                risk_level = 'extreme'
            elif remaining_hours <= total_hours_predicted * 0.5:
                risk_level = 'high'
            elif remaining_hours <= total_hours_predicted * 0.75:
                risk_level = 'medium'
            else:
                risk_level = 'low'

            response.append((progress.matiere, risk_level))

    response.sort(key=lambda x: risk_levels[x[1]])

    response_formatted = [f"{matiere} is in {risk_level} risk" for matiere, risk_level in response]
    return {'navbar_data': response_formatted}
