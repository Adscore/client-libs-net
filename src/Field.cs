namespace AdScore.Signature
{
    public class Field
    {
        public string Name { get; set; }

        public string Type { get; set; }

        public Field(string name, string type)
        {
            Name = name;
            Type = type;
        }
    }
}