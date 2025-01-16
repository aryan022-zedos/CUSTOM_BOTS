import discord
from discord.ext import commands, tasks
import asyncio
from datetime import datetime, timedelta
import re
import time
import config
import sqlite3
import random
from discord.ui import Select, View

intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.members = True
intents.message_content = True
intents.reactions = True

bot = commands.Bot(command_prefix=".d", intents=intents)
bot.remove_command("help") 

# Database setup
conn = sqlite3.connect("moderation.db")
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS warnings (
    user_id INTEGER,
    guild_id INTEGER,
    reason TEXT,
    timestamp TEXT
)''')
conn.commit()

# Configuration
MESSAGE_LIMIT = 5
TIME_WINDOW = 10  # seconds
BAD_WORDS = ["badword1", "badword2"]  # Add offensive words here
MALICIOUS_LINKS = ["phishing.com", "malicious.com"]  # Add malicious domains here
RAID_JOIN_LIMIT = 5  # Number of users joining within TIME_WINDOW to trigger a raid
user_messages = {}
recent_joins = []

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Game(name="with your mom's pussy"))
    print(f"Logged in as {bot.user}")
    print("Bot is ready to secure the server!")


@bot.event
async def on_invite_create(invite):
    log_channel = discord.utils.get(invite.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"New invite created by {invite.inviter.mention}: {invite.url}")

@bot.event
async def on_invite_delete(invite):
    log_channel = discord.utils.get(invite.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"Invite deleted: {invite.url}")


# Anti-spam mechanism
@bot.event
async def on_message(message):
    if message.author.bot:
        return

    user_id = message.author.id
    guild_id = message.guild.id
    now = datetime.utcnow()

    # Anti-spam check
    if user_id not in user_messages:
        user_messages[user_id] = []
    user_messages[user_id].append(now)
    user_messages[user_id] = [msg_time for msg_time in user_messages[user_id] if now - msg_time < timedelta(seconds=TIME_WINDOW)]

    if len(user_messages[user_id]) > MESSAGE_LIMIT:
        await message.delete()
        await message.channel.send(f"{message.author.mention}, you're sending messages too quickly. Slow down!")
        log_action(guild_id, user_id, "Anti-spam triggered")

    # Profanity filter
    if any(bad_word in message.content.lower() for bad_word in BAD_WORDS):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, your message contained inappropriate language and was removed.")
        log_action(guild_id, user_id, "Used profanity")

    # Malicious link detection
    if any(link in message.content.lower() for link in MALICIOUS_LINKS):
        await message.delete()
        await message.channel.send(f"{message.author.mention}, sharing malicious links is not allowed.")
        log_action(guild_id, user_id, "Shared malicious link")

    await bot.process_commands(message)

# Raid detection
@bot.event
async def on_member_join(member):
    guild = member.guild
    log_channel = discord.utils.get(guild.text_channels, name="security-logs")
    now = datetime.utcnow()
    recent_joins.append(now)
    recent_joins[:] = [join_time for join_time in recent_joins if now - join_time < timedelta(seconds=TIME_WINDOW)]

    if len(recent_joins) > RAID_JOIN_LIMIT:
        for join_time in recent_joins:
            if member.joined_at == join_time:
                await member.kick(reason="Possible raid account.")
                if log_channel:
                    await log_channel.send(f"Kicked {member.mention} for suspected raid activity.")

@bot.event
async def on_member_remove(member):
    guild = member.guild
    log_channel = discord.utils.get(guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"Member left: {member.mention} ({member.id})")

# Warn command
@bot.command()
@commands.has_permissions(manage_messages=True)
async def warn(ctx, member: discord.Member, *, reason="Violation of rules"):
    guild_id = ctx.guild.id
    user_id = member.id
    timestamp = datetime.utcnow().isoformat()

    c.execute("INSERT INTO warnings (user_id, guild_id, reason, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, guild_id, reason, timestamp))
    conn.commit()

    await ctx.send(f"{member.mention} has been warned for: {reason}")
    log_action(guild_id, user_id, f"Warned: {reason}")

    log_channel = discord.utils.get(ctx.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"User {member.mention} was warned for: {reason}")

# Setup logs command
@bot.command()
@commands.has_permissions(administrator=True)
async def setup_logs(ctx):
    guild = ctx.guild
    existing_channel = discord.utils.get(guild.text_channels, name="security-logs")

    if existing_channel:
        await ctx.send("The security-logs channel already exists!")
        return

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True)
    }

    log_channel = await guild.create_text_channel("security-logs", overwrites=overwrites)
    await ctx.send(f"Security logs channel created: {log_channel.mention}")

    await log_channel.send("This channel has been set up for security logs.")

# Additional security commands
@bot.command()
@commands.has_permissions(manage_channels=True)
async def lockdown(ctx):
    """Lock the current channel for everyone except admins."""
    overwrites = ctx.channel.overwrites_for(ctx.guild.default_role)
    overwrites.send_messages = False
    await ctx.channel.set_permissions(ctx.guild.default_role, overwrite=overwrites)
    await ctx.send("This channel has been locked down.")

@bot.command()
@commands.has_permissions(manage_channels=True)
async def unlock(ctx):
    """Unlock the current channel for everyone."""
    overwrites = ctx.channel.overwrites_for(ctx.guild.default_role)
    overwrites.send_messages = True
    await ctx.channel.set_permissions(ctx.guild.default_role, overwrite=overwrites)
    await ctx.send("This channel has been unlocked.")

@bot.command()
@commands.has_permissions(manage_roles=True)
async def mute(ctx, member: discord.Member, *, reason="Violation of rules"):
    """Mute a member."""
    guild = ctx.guild
    mute_role = discord.utils.get(guild.roles, name="Muted")

    if not mute_role:
        mute_role = await guild.create_role(name="Muted")
        for channel in guild.channels:
            await channel.set_permissions(mute_role, send_messages=False, speak=False)

    await member.add_roles(mute_role, reason=reason)
    await ctx.send(f"{member.mention} has been muted. Reason: {reason}")

@bot.command()
@commands.has_permissions(manage_roles=True)
async def unmute(ctx, member: discord.Member):
    """Unmute a member."""
    mute_role = discord.utils.get(ctx.guild.roles, name="Muted")
    if mute_role in member.roles:
        await member.remove_roles(mute_role)
        await ctx.send(f"{member.mention} has been unmuted.")
    else:
        await ctx.send(f"{member.mention} is not muted.")

@bot.command()
@commands.has_permissions(administrator=True)
async def purge(ctx, limit: int):
    """Bulk delete messages in a channel."""
    await ctx.channel.purge(limit=limit)
    await ctx.send(f"Deleted {limit} messages.", delete_after=5)

@bot.command()
@commands.has_permissions(kick_members=True)
async def kick(ctx, member: discord.Member, *, reason="Violation of rules"):
    """Kick a member from the server."""
    await member.kick(reason=reason)
    await ctx.send(f"{member.mention} has been kicked. Reason: {reason}")

@bot.command()
@commands.has_permissions(ban_members=True)
async def ban(ctx, member: discord.Member, *, reason="Violation of rules"):
    """Ban a member from the server."""
    await member.ban(reason=reason)
    await ctx.send(f"{member.mention} has been banned. Reason: {reason}")

@bot.command()
@commands.has_permissions(ban_members=True)
async def unban(ctx, *, member_name):
    """Unban a member from the server."""
    banned_users = await ctx.guild.bans()
    for ban_entry in banned_users:
        user = ban_entry.user
        if user.name == member_name:
            await ctx.guild.unban(user)
            await ctx.send(f"{user.mention} has been unbanned.")
            return
    await ctx.send(f"User {member_name} not found in the ban list.")

@bot.command()
@commands.has_permissions(manage_guild=True)
async def slowmode(ctx, seconds: int):
    """Set slowmode delay for the current channel."""
    await ctx.channel.edit(slowmode_delay=seconds)
    await ctx.send(f"Set slowmode to {seconds} seconds.")

# Log action function
def log_action(guild_id, user_id, action):
    print(f"[LOG] Guild {guild_id} | User {user_id} | Action: {action}")

@bot.command()
@commands.has_permissions(administrator=True)
async def antinuke(ctx, action: str = "on"):
    """Enable or disable Anti-Nuke mode."""
    if action.lower() == "on":
        bot.anti_nuke = True
        await ctx.send("Anti-Nuke mode enabled.")
    elif action.lower() == "off":
        bot.anti_nuke = False
        await ctx.send("Anti-Nuke mode disabled.")
    else:
        await ctx.send("Invalid option. Use 'on' or 'off'.")

@bot.command()
@commands.has_permissions(administrator=True)
async def scan_server(ctx):
    """Scan the server for potential threats."""
    suspicious_users = []
    for member in ctx.guild.members:
        if member.bot or member.guild_permissions.administrator:
            continue
        if len(member.roles) == 1:  # Only @everyone
            suspicious_users.append(member.mention)
    if suspicious_users:
        await ctx.send(f"Suspicious users detected: {', '.join(suspicious_users)}")
    else:
        await ctx.send("No suspicious users found.")

@bot.command()
async def report(ctx, message_id: int, *, reason: str):
    """Report a message for moderation review."""
    try:
        message = await ctx.channel.fetch_message(message_id)
        log_channel = discord.utils.get(ctx.guild.text_channels, name="security-logs")
        if log_channel:
            await log_channel.send(
                f"Reported Message: {message.content}\nAuthor: {message.author.mention}\nReason: {reason}"
            )
            await ctx.send("The message has been reported.")
        else:
            await ctx.send("Security logs channel not found.")
    except discord.NotFound:
        await ctx.send("Message not found.")


bot.admins = []

@bot.command()
@commands.has_permissions(administrator=True)
async def set_admins(ctx, *members: discord.Member):
    """Set bot administrators."""
    bot.admins = [member.id for member in members]
    await ctx.send(f"Bot admins set: {', '.join(member.mention for member in members)}")


@bot.command()
@commands.has_permissions(administrator=True)
async def revoke_perms(ctx, member: discord.Member):
    """Revoke admin permissions from a user."""
    admin_roles = [role for role in ctx.guild.roles if role.permissions.administrator]
    for role in admin_roles:
        if role in member.roles:
            await member.remove_roles(role)
            await ctx.send(f"Removed admin permissions from {member.mention}.")
            return
    await ctx.send(f"{member.mention} does not have admin permissions.")


@bot.event
async def on_message_edit(before, after):
    if before.content != after.content:
        log_channel = discord.utils.get(before.guild.text_channels, name="security-logs")
        if log_channel:
            await log_channel.send(f"Message edited by {before.author.mention}: \n**Before:** {before.content}\n**After:** {after.content}")

@bot.event
async def on_message_delete(message):
    log_channel = discord.utils.get(message.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"Message deleted by {message.author.mention}: \n**Content:** {message.content}")


bot.whitelisted = []

@bot.command()
@commands.has_permissions(administrator=True)
async def whitelist(ctx, *members: discord.Member):
    """Whitelist members to bypass security checks."""
    bot.whitelisted = [member.id for member in members]
    await ctx.send(f"Whitelisted: {', '.join(member.mention for member in members)}")

@bot.command()
@commands.has_permissions(administrator=True)
async def check_role_perms(ctx, role: discord.Role):
    """Display permissions of a role."""
    perms = [perm.replace("_", " ").title() for perm, value in role.permissions if value]
    if perms:
        await ctx.send(f"Permissions for {role.name}: {', '.join(perms)}")
    else:
        await ctx.send(f"{role.name} has no permissions.")

@bot.command()
@commands.has_permissions(administrator=True)
async def audit_admins(ctx):
    """List all members with admin permissions."""
    admins = [member.mention for member in ctx.guild.members if member.guild_permissions.administrator]
    if admins:
        await ctx.send(f"Admins in the server: {', '.join(admins)}")
    else:
        await ctx.send("No admins found in the server.")




@bot.command()
@commands.has_permissions(administrator=True)
async def set_join_age(ctx, days: int):
    """Set minimum account age for joining the server."""
    bot.join_age_limit = timedelta(days=days)
    await ctx.send(f"Accounts must now be at least {days} days old to join.")

@bot.event
async def on_member_join(member):
    account_age = datetime.utcnow() - member.created_at
    if hasattr(bot, 'join_age_limit') and account_age < bot.join_age_limit:
        await member.kick(reason="Account too new.")
        log_channel = discord.utils.get(member.guild.text_channels, name="security-logs")
        if log_channel:
            await log_channel.send(f"Kicked {member.mention} for being too new.")

@bot.event
async def on_guild_channel_delete(channel):
    log_channel = discord.utils.get(channel.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"Channel deleted: {channel.name}")

@bot.event
async def on_guild_role_delete(role):
    log_channel = discord.utils.get(role.guild.text_channels, name="security-logs")
    if log_channel:
        await log_channel.send(f"Role deleted: {role.name}")

# Dropdown menu class
class HelpDropdown(Select):
    def __init__(self):
        # Define the dropdown menu options
        options = [
            discord.SelectOption(label="💭 General Commands", description="View general bot commands."),
            discord.SelectOption(label="⚒️ Moderation Commands", description="View moderation-related commands."),
            discord.SelectOption(label="👮🏻 Security Commands", description="View advanced security commands."),
            discord.SelectOption(label="💸 Economy Commands", description="View economy-related commands."),
            discord.SelectOption(label="🔒 Premium Commands", description="View premium-only commands."),
        ]
        super().__init__(
            placeholder="Choose a command category...",
            min_values=1,
            max_values=1,
            options=options,
        )

    async def callback(self, interaction: discord.Interaction):
        # Display the command list based on the selected category
        if self.values[0] == "💭 General Commands":
            embed = discord.Embed(
                title="General Commands",
                description=(
                    "`help` - Display this help menu.\n"
                    "`ping` - Check the bot's latency.\n"
                    "`botinfo` - Get information about the server.\n"
                    "`user_guide` - Take the user guide."
                ),
                color=discord.Color.blue(),
            )
        elif self.values[0] == "⚒️ Moderation Commands":
            embed = discord.Embed(
                title="Moderation Commands",
                description=(
                    "`kick` - Kick a user from the server.\n"
                    "`ban` - Ban a user from the server.\n"
                    "`unban` - Unban a user from the server.\n"
                    "`mute` - Mute a user.\n"
                    "`unmute` - Unmute a user.\n"
                    "`lockdown` - Lock a channel.\n"
                    "`unlock` - Unlock a channel."
                ),
                color=discord.Color.red(),
            )
        elif self.values[0] == "👮🏻 Security Commands":
            embed = discord.Embed(
                title="Security Commands",
                description=(
                    "`scan_server` - Scan for potential threats.\n"
                    "`antinuke` - Enable/disable Anti-Nuke mode.\n"
                    "`revoke_perms` - Revoke admin permissions from a user.\n"
                    "`set_join_age` - Set minimum account age for joining.\n"
                    "`clear_roles` - Remove all roles from a user.\n"
                    "`audit_admins` - List all admins in the server.\n"
                    "`setup_logs` - setup the logs channel."
                ),
                color=discord.Color.green(),
            )
        elif self.values[0] == "💸 Economy Commands":
            embed = discord.Embed(
                title="Economy Commands",
                description=(
                    "`balance` - Check your coin balance.\n"
                    "`give @user amount` - Give coins to another user.\n"
                    "`daily` - Receive daily coins as a reward.\n"
                    "`shop` - View available items in the shop.\n"
                    "`buy item_name` - Buy an item from the shop.\n"
                    "`inventory` - Check the items in your inventory.\n"
                    "`gamble amount` - Gamble coins by guessing heads or tails.\n"
                    "`transfer @user amount` - Transfer coins to another user.\n"
                    "`leaderboard` - View the top users based on coin balance.\n"
                ),
                color=discord.Color.gold(),
            )
        elif self.values[0] == "🔒 Premium Commands":
            embed = discord.Embed(
                title="Premium Commands",
                description=(
                    "`buy_premium` - Buy a premium subscription.\n"
                    "`premium_command` - Access exclusive premium-only commands.\n"
                    "`premium_shop` - View the premium items in the shop.\n"
                ),
                color=discord.Color.purple(),
            )
        else:
            embed = discord.Embed(
                title="Error",
                description="Invalid selection.",
                color=discord.Color.orange(),
            )

        # Send the embed as a response
        await interaction.response.edit_message(embed=embed, view=self.view)


class HelpView(View):
    def __init__(self):
        super().__init__()
        self.add_item(HelpDropdown())


@bot.command()
async def help(ctx):
    """Display the help menu with a dropdown."""
    embed = discord.Embed(
        title=f"{bot.user.name}'s command panel.",
        color=0x00ffb3,
    )
    embed.set_footer(text="Make with ❤️ in discord.py library.", icon_url="https://cdn.discordapp.com/avatars/1329156330082144256/a_7cadcf0ed585f409260568d2fc3624bc.gif?size=1024")
    embed.add_field(name="<:BabyPinkArrowRight:1327371287672127519> __Available Commands:__ ",value="> General commands \n > Moderation Commands \n > Security Commands \n > Economy commands")
    view = HelpView()
    await ctx.send(embed=embed, view=view)

@bot.command()
async def ping(ctx):
    """Check the bot's latency."""
    latency = round(bot.latency * 1000)  # Latency in ms
    embed = discord.Embed(
        title="Pong! 🏓",
        description=f"Latency: `{latency}ms`",
        color=discord.Color.blurple()
    )
    await ctx.send(embed=embed)

@bot.command()
async def botinfo(ctx):
    """Display information about the bot."""
    embed = discord.Embed(
        title="Bot Information",
        description="Details about this bot.",
        color=discord.Color.green()
    )
    embed.add_field(name="Bot Name", value=bot.user.name, inline=True)
    embed.add_field(name="Bot ID", value=bot.user.id, inline=True)
    embed.add_field(name="Guild Count", value=len(bot.guilds), inline=True)
    embed.add_field(name="Developer", value="zedotix_45362", inline=True)  # Replace with your name
    embed.add_field(name="Latency", value=f"{round(bot.latency * 1000)}ms", inline=True)
    embed.set_thumbnail(url=bot.user.avatar.url)
    embed.set_footer(text=f"Requested by {ctx.author}", icon_url=ctx.author.avatar.url)

    await ctx.send(embed=embed)

@bot.command()
async def user_guide(ctx):
    embed=discord.Embed(
        title="Guide to use me:",
        description="type `.d<command_name>` to use. \nFor further consultation click [`here`](<https://discord.gg/wWEpmpgW6k>)",
        color=0x00ffb3
    )
    await ctx.send(embed=embed)



# Create a dictionary for users' balances and items
economy_data = {}
premium_users = {}

# Helper function to get user data
def get_user_data(user_id):
    if user_id not in economy_data:
        economy_data[user_id] = {'balance': 0, 'inventory': []}
    return economy_data[user_id]

# Command to check balance
@bot.command()
async def balance(ctx):
    user_data = get_user_data(ctx.author.id)
    await ctx.send(f"{ctx.author.name}, your balance is {user_data['balance']} coins.")

# Command to give coins to a user
@bot.command()
async def give(ctx, member: discord.Member, amount: int):
    if amount <= 0:
        await ctx.send("You can't give negative or zero coins!")
        return

    giver_data = get_user_data(ctx.author.id)
    if giver_data['balance'] < amount:
        await ctx.send("You don't have enough coins!")
        return

    giver_data['balance'] -= amount
    receiver_data = get_user_data(member.id)
    receiver_data['balance'] += amount
    await ctx.send(f"{ctx.author.name} gave {amount} coins to {member.name}.")

# Command to send daily coins
@bot.command()
async def daily(ctx):
    user_data = get_user_data(ctx.author.id)
    reward = random.randint(50, 100)
    user_data['balance'] += reward
    await ctx.send(f"Here is your daily reward of {reward} coins, {ctx.author.name}! Your new balance is {user_data['balance']}.")

# Command to shop and buy items
@bot.command()
async def shop(ctx):
    shop_items = {
        "Sword": 150,
        "Shield": 100,
        "Potion": 50
    }
    shop_message = "Welcome to the shop! Here are the items available for purchase:\n"
    for item, price in shop_items.items():
        shop_message += f"{item}: {price} coins\n"
    
    await ctx.send(shop_message)

# Command to buy an item from the shop
@bot.command()
async def buy(ctx, item_name: str):
    shop_items = {
        "Sword": 150,
        "Shield": 100,
        "Potion": 50
    }
    if item_name not in shop_items:
        await ctx.send("This item is not available in the shop.")
        return

    user_data = get_user_data(ctx.author.id)
    price = shop_items[item_name]
    if user_data['balance'] < price:
        await ctx.send(f"You don't have enough coins to buy {item_name}.")
        return

    user_data['balance'] -= price
    user_data['inventory'].append(item_name)
    await ctx.send(f"Congratulations {ctx.author.name}, you bought a {item_name}.")

# Command to check inventory
@bot.command()
async def inventory(ctx):
    user_data = get_user_data(ctx.author.id)
    if not user_data['inventory']:
        await ctx.send("Your inventory is empty.")
    else:
        inventory_message = "Your inventory contains:\n"
        for item in user_data['inventory']:
            inventory_message += f"- {item}\n"
        await ctx.send(inventory_message)

# Gambling: Flip a coin
@bot.command()
async def gamble(ctx, bet: int):
    user_data = get_user_data(ctx.author.id)
    if bet <= 0:
        await ctx.send("You can't gamble negative or zero coins!")
        return
    if user_data['balance'] < bet:
        await ctx.send("You don't have enough coins to gamble.")
        return

    result = random.choice(['Heads', 'Tails'])
    guess = random.choice(['Heads', 'Tails'])

    if guess == result:
        user_data['balance'] += bet
        await ctx.send(f"You guessed {guess} and won! Your new balance is {user_data['balance']}.")
    else:
        user_data['balance'] -= bet
        await ctx.send(f"You guessed {guess} and lost! Your new balance is {user_data['balance']}.")

# Transfer coins to another user
@bot.command()
async def transfer(ctx, member: discord.Member, amount: int):
    if amount <= 0:
        await ctx.send("You can't transfer negative or zero coins!")
        return

    sender_data = get_user_data(ctx.author.id)
    if sender_data['balance'] < amount:
        await ctx.send("You don't have enough coins to transfer.")
        return

    sender_data['balance'] -= amount
    receiver_data = get_user_data(member.id)
    receiver_data['balance'] += amount
    await ctx.send(f"{ctx.author.name} transferred {amount} coins to {member.name}.")

# Command to check the leaderboard
@bot.command()
async def leaderboard(ctx):
    sorted_users = sorted(economy_data.items(), key=lambda x: x[1]['balance'], reverse=True)
    leaderboard_message = "Leaderboard:\n"
    for i, (user_id, user_data) in enumerate(sorted_users[:5], 1):
        member = await bot.fetch_user(user_id)
        leaderboard_message += f"{i}. {member.name}: {user_data['balance']} coins\n"
    
    await ctx.send(leaderboard_message)

# Command to purchase premium
@bot.command()
async def buy_premium(ctx):
    """Allow users to buy premium subscription using coins."""
    premium_cost = 50000  # Set premium cost
    user_data = get_user_data(ctx.author.id)
    
    if user_data['balance'] < premium_cost:
        await ctx.send(f"Sorry {ctx.author.name}, you don't have enough coins to buy premium. You need {premium_cost} coins.")
        return

    # Deduct the cost and mark the user as premium
    user_data['balance'] -= premium_cost
    premium_users[ctx.author.id] = True  # Grant premium status to the user
    await ctx.send(f"Congratulations {ctx.author.name}, you've purchased a premium subscription!")

# Command to check if a user has premium
def is_premium(ctx):
    return premium_users.get(ctx.author.id, False)

# Premium command example
@bot.command()
async def premium_command(ctx):
    """A premium-only command."""
    if not is_premium(ctx):
        await ctx.send("Sorry, you need to buy a premium subscription to use this command.")
        return

    # Premium command logic
    await ctx.send(f"Welcome to the premium section, {ctx.author.name}! Here's a special reward for you!")

# Example of a command available only to premium users
@bot.command()
async def premium_shop(ctx):
    """A premium-only shop."""
    if not is_premium(ctx):
        await ctx.send("Sorry, you need to buy a premium subscription to access the premium shop.")
        return
    
    # Premium shop items
    premium_items = {
        "Premium Sword": 1000,
        "Premium Shield": 800,
        "Premium Potion": 400
    }
    premium_shop_message = "Welcome to the premium shop! Here are the items available for purchase:\n"
    for item, price in premium_items.items():
        premium_shop_message += f"{item}: {price} coins\n"
    
    await ctx.send(premium_shop_message)





@bot.event
async def on_message(message):
    """Detect potential self-bot activity."""
    if message.author.bot or message.channel.type == discord.ChannelType.private:
        return

    # Heuristic to identify self-bot behavior
    if len(message.content) > 200 or "http" in message.content:
        log_channel = discord.utils.get(message.guild.text_channels, name="security-logs")
        if log_channel:
            embed = discord.Embed(
                title="🚨 Potential Self-Bot Detected!",
                description=f"User: {message.author.mention}\nMessage: `{message.content[:100]}...`",
                color=discord.Color.red(),
            )
            embed.set_footer(text=f"User ID: {message.author.id}")
            await log_channel.send(embed=embed)

    await bot.process_commands(message)  # Ensure other commands are processed



# Error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You don't have permission to use this command.")
    elif isinstance(error, commands.CommandNotFound):
        await ctx.send("Command not found.")
    else:
        await ctx.send(f"An error occurred: {error}")

# Replace 'YOUR_TOKEN_HERE' with your bot token
bot.run(config.TOKEN)
