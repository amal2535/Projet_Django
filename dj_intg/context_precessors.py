import random
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from datetime import timedelta, datetime
from .models import Progress
from django.http import JsonResponse
from django.contrib.auth.models import AnonymousUser

motivational_quotes_study = [
    {"quote": "The future belongs to those who believe in the beauty of their dreams.", "author": "Eleanor Roosevelt"},
    {"quote": "Education is the most powerful weapon which you can use to change the world.", "author": "Nelson Mandela"},
    {"quote": "The more that you read, the more things you will know. The more that you learn, the more places you’ll go.", "author": "Dr. Seuss"},
    {"quote": "Study hard, for the well is deep, and our brains are shallow.", "author": "Richard Baxter"},
    {"quote": "The expert in anything was once a beginner.", "author": "Helen Hayes"},
    {"quote": "Push yourself, because no one else is going to do it for you.", "author": ""},
    {"quote": "Success is the sum of small efforts, repeated day in and day out.", "author": "Robert Collier"},
    {"quote": "Don't watch the clock; do what it does. Keep going.", "author": "Sam Levenson"},
    {"quote": "The only place where success comes before work is in the dictionary.", "author": "Vidal Sassoon"},
    {"quote": "Believe you can and you're halfway there.", "author": "Theodore Roosevelt"}
]

motivational_quotes_success = [
    {"quote": "Success is not the key to happiness. Happiness is the key to success. If you love what you are doing, you will be successful.", "author": "Albert Schweitzer"},
    {"quote": "The only limit to our realization of tomorrow is our doubts of today.", "author": "Franklin D. Roosevelt"},
    {"quote": "Don't be afraid to give up the good to go for the great.", "author": "John D. Rockefeller"},
    {"quote": "Success usually comes to those who are too busy to be looking for it.", "author": "Henry David Thoreau"},
    {"quote": "Opportunities don't happen. You create them.", "author": "Chris Grosser"},
    {"quote": "Success is not how high you have climbed, but how you make a positive difference to the world.", "author": "Roy T. Bennett"},
    {"quote": "I find that the harder I work, the more luck I seem to have.", "author": "Thomas Jefferson"},
    {"quote": "Success is walking from failure to failure with no loss of enthusiasm.", "author": "Winston Churchill"},
    {"quote": "The way to get started is to quit talking and begin doing.", "author": "Walt Disney"},
    {"quote": "Your time is limited, don't waste it living someone else’s life.", "author": "Steve Jobs"}
]


@login_required
def navbar_data(request):
    if not request.user.is_authenticated:
        return {'error': 'No progress data found for the current user.'}

    user_progress = Progress.objects.filter(user=request.user)

    if not user_progress.exists():
        return {'error': 'No progress data found for the current user.'}

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

            quote = random.choice(motivational_quotes_study + motivational_quotes_success)
            
            response.append({
                'matiere': progress.matiere,
                'risk_level': risk_level,
                'quote': quote
            })

    if not response:
        return {'message': 'No exams found within the risk calculation criteria.'}

    response.sort(key=lambda x: risk_levels.get(x['risk_level'], 999))

    return {'navbar_data': response}
