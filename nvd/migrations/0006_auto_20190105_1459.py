# Generated by Django 2.1.3 on 2019-01-05 14:59

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('nvd', '0005_assessment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='assessment',
            name='vulnerability',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='assessments', to='nvd.Vulnerability', verbose_name='Vulnerability'),
        ),
    ]
