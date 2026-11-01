# held-out heldout_30 (CWE-78): Popen of an argv list split from a "docker stop" string built from a stored container id
import subprocess

from django.http import JsonResponse
from django.shortcuts import redirect
from django.views.generic import View

from .models import Lesson, UserLesson


class LessonRunner(View):
    def delete(self, request, lesson):
        if not request.user.is_authenticated:
            return redirect("login")

        try:
            item = Lesson.objects.get(name=lesson)
            user_item = UserLesson.objects.get(user=request.user, lesson=item)
        except Exception:
            return JsonResponse({"message": "failed", "status": "500"})

        user_item.is_live = False
        user_item.save()
        command = f"docker stop {user_item.container_id}"
        process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)
        output, error = process.communicate()
        return JsonResponse({"message": "success", "status": "200"})
