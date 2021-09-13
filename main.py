import pytz
import pyperclip as pc
import hashlib
from datetime import datetime
from flask import *
from flask_bootstrap import Bootstrap
from faunadb import query as q
from faunadb.client import FaunaClient
from decouple import config
from functools import wraps


app = Flask(__name__)
Bootstrap(app)
app.config["SECRET_KEY"] = config('SECRET_KEY')
client = FaunaClient(secret=config('FAUNA_KEY'))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            flash("Please login before accessing that page!", "danger")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    return decorated






@app.route("/register/", methods=["GET", "POST"])
def register():
    username = ''

    if request.method == "POST":
        username = request.form.get("username").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        next_url = request.form.get("next")

        upper_result = any(letter.isupper() for letter in password)
        lower_result = any(letter.islower() for letter in password)
        digit_result = any(letter.isdigit() for letter in password)
        printable_result = any(letter.isprintable() for letter in password)

        if upper_result and lower_result and digit_result and printable_result and len(password) >= 8:

            if password != confirm_password:
                flash("Your passwords does not match!", "danger")
                return render_template("register.html", username=username)

            try:
                _ = client.query(
                    q.get(q.match(q.index("users_index"), username)))
                flash("The account you are trying to create already exists!", "danger")
            except:
                _ = client.query(q.create(q.collection("Users"), {
                    "data": {
                        "username": username,
                        "password": hashlib.sha512(password.encode()).hexdigest(),
                        "date": datetime.now(pytz.UTC)
                    }
                }))
                flash(
                    "You have successfully created your account, you can now create online elections!", "success")

            return redirect(url_for("login", next=next_url))

        else:
            flash("Make sure your password follows the required format!", "danger")
            return render_template("register.html", username=username)

    return render_template("register.html", username=username)






@app.route("/login/", methods=["GET", "POST"])
@app.route("/", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username").strip().lower()
        password = request.form.get("password")
        next_url = request.form.get("next")

        try:
            user = client.query(
                q.get(q.match(q.index("users_index"), username)))
            if hashlib.sha512(password.encode()).hexdigest() == user["data"]["password"]:
                session["user"] = {
                    "id": user["ref"].id(),
                    "username": user["data"]["username"]
                }
                
                if next_url:
                    return redirect(next_url)

                redirect(url_for('dashboard'))

            else:
                flash(
                "You have supplied invalid login credentials, please try again!", "danger")
        except:
            flash(
                "Network error, try again", "danger")
        return redirect(url_for("login", next=next_url))

    return render_template("login.html")






@app.route("/dashboard/create_election/", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title = request.form.get("title").strip()
        voting_options = request.form.get("voting-options").strip()

        options = {}
        for i in voting_options.split("\n"):
            options[i.strip()] = 0

        _ = client.query(q.create(q.collection("Elections"), {
            "data": {
                "creator": session["user"]["username"],
                "title": title,
                "voting_options": options,
                "voters": [],
                "date": datetime.now(pytz.UTC)
            }
        }))
        return redirect(url_for("dashboard"))

    return render_template("create_election.html")






@app.route("/election/<int:election_id>/", methods=["GET", "POST"])
@login_required
def election(election_id):
    try:
        election = client.query(
            q.get(q.ref(q.collection("Elections"), election_id)))

        if election["data"]["creator"] != session["user"]["username"]:
            return redirect(url_for('vote', election_id=election_id))
        else:
            return redirect(url_for('view_single_election', election_id=election_id))

    except:
        return render_template('404.html')
    





@app.route("/my_election/<int:election_id>/", methods=["GET", "POST"])
@login_required
def view_single_election(election_id):
    try:
        election = client.query(q.get(q.ref(q.collection("Elections"), election_id)))
        url = request.url
        new_url = url.replace("my_election", "election")
        return render_template("single_election.html", election=election, url=new_url)

    except:
        return render_template('404.html')
    
    



@app.route("/copy_election/<int:election_id>/", methods=["GET", "POST"])
@login_required
def copy_link(election_id):
    url = request.url
    new_url = url.replace("copy_election", "election")
    pc.copy(new_url)
    flash("Link copied to clipboard", "success")

    return redirect(url_for("view_single_election", election_id=election_id))






@app.route("/delete_election/<int:election_id>/")
@login_required
def delete_election(election_id):
    try:
        _ = client.query(
            q.get(q.ref(q.collection("Elections"), election_id)))
    except:
        return render_template('404.html')

    _ = client.query(q.delete(q.ref(q.collection("Elections"), election_id)))
    flash("The election have been deleted", "success")

    return redirect(url_for("dashboard"))






@app.route("/vote/<int:election_id>/", methods=["GET", "POST"])
@login_required
def vote(election_id):
    try:
        election = client.query(
            q.get(q.ref(q.collection("Elections"), election_id)))

        if session["user"]["username"] in election["data"]["voters"]:
            flash("You have voted for this election before!", 'info')
            return redirect(url_for('view_other_election'))

    except:
        return render_template('404.html')
    

    if request.method == "POST":
        vote = request.form.get("vote").strip()
        election["data"]["voting_options"][vote] += 1
        election["data"]["voters"].append(session["user"]["username"])
        client.query(q.update(q.ref(q.collection("Elections"), election_id), {
                     "data": {"voting_options": election["data"]["voting_options"], "voters":election["data"]["voters"]}}))
        flash("Your vote was successfully recorded!", "success")
        return redirect(url_for("view_other_election"))

    return render_template("vote.html", election=election["data"])






@app.route("/dashboard/", methods=["GET"])
@login_required
def dashboard():

    elections = client.query(q.paginate(
        q.match(q.index("election_index"), session["user"]["username"])))

    elections_ref = []
    for i in elections["data"]:
        elections_ref.append(q.get(q.ref(q.collection("Elections"), i.id())))

    return render_template("dashboard.html", elections=client.query(elections_ref), length=lambda x: len(x))






@app.route("/view_other_elections/", methods=["GET"])
@login_required
def view_other_election():

    elections = client.query(q.paginate(q.documents(q.collection("Elections"))))
    elections_ref = []
    for i in elections["data"]:
        elections_ref.append(q.get(q.ref(q.collection("Elections"), i.id())))

    total_elections = client.query(elections_ref)

    return render_template("view_other_elections.html", total_elections=total_elections)






@app.route("/view_my_elections/", methods=["GET"])
@login_required
def view_my_election():
    elections = client.query(q.paginate(
        q.match(q.index("election_index"), session["user"]["username"])))

    elections_ref = []
    for i in elections["data"]:
        elections_ref.append(q.get(q.ref(q.collection("Elections"), i.id())))

    return render_template("view_my_elections.html", elections=client.query(elections_ref))






@app.route("/account/", methods=["POST", "GET"])
@login_required
def account():
    if request.method == "POST":
        username = request.form.get("username").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        upper_result = any(letter.isupper() for letter in password)
        lower_result = any(letter.islower() for letter in password)
        digit_result = any(letter.isdigit() for letter in password)
        printable_result = any(letter.isprintable() for letter in password)

        if password != confirm_password:
                        flash("Your passwords does not match!", "danger")
                        return render_template("register.html", username=username)


        try:
            _ = client.query(
                q.get(q.match(q.index("users_index"), username)))
            flash("The name you are trying to choose already exists!", "danger")
        except:
            if password != '' or password != ' ' and username == session['user']['username']:
                if upper_result and lower_result and digit_result and printable_result and len(password) >= 8:
                    user = client.query(q.update(q.ref(q.collection("Users"), session['user']['username']), {
                        "data": {
                        "password": hashlib.sha512(password.encode()).hexdigest(),
                    }}))
                else:
                    flash("Make sure your password follows the required format!", "danger")
                    return render_template("register.html", username=username)

            elif password == '' or password == ' ' and username != session['user']['username']:
                user = client.query(q.update(q.ref(q.collection("Users"), session['user']['username']), {
                        "data": {
                        "username": username
                    }}))

            elif password != '' or password != ' ' and username != session['user']['username']:
                if upper_result and lower_result and digit_result and printable_result and len(password) >= 8:
                    user = client.query(q.update(q.ref(q.collection("Users"), session['user']['username']), {
                            "data": {
                            "username": username,
                            "password": hashlib.sha512(password.encode()).hexdigest()
                        }}))
                else:
                    flash("Make sure your password follows the required format!", "danger")
                    return render_template("register.html", username=username)
        

            session["user"] = {
                "id": user["ref"].id(),
                "username": user["data"]["username"]
            }

            flash("You have successfully updated your account details!", "success")
    else:
        username = session['user']['username']
        
    return render_template("account.html", username=username)






@app.route("/delete_account//<int:user_id>/", methods=['POST', 'GET'])
@login_required
def delete_account(user_id):

    _ = client.query(q.delete(q.ref(q.collection("Users"), user_id)))
    flash("The Your account have been deleted successfully", "success")

    return redirect(url_for("dashboard"))






@app.route("/logout/")
@login_required
def logout():
    if "user" not in session:
        return redirect(url_for("login"))

    del session['user']

    return redirect(url_for('login'))










